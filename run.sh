#!/bin/bash
#author yaozhongjie (integrated Nginx 1.31.9 auto-upgrade & modern Let's Encrypt)

TARGET_NGINX_VER="1.31.9"
OPENSSL_VER="3.0.15"

exiterr() {
    echo "错误: $1"
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    exiterr "请使用 root 用户运行此脚本。"
fi

fix_debian11_sources() {
    if grep -q "bullseye" /etc/os-release 2>/dev/null; then
        sed -i -E '/bullseye-(security|backports)/s/^/#/' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
    fi
}

install_pkg() {
    local pkg="$1"
    if command -v apt-get >/dev/null 2>&1; then
        fix_debian11_sources
        apt-get update || true
        apt-get -y install "$pkg" || exiterr "安装 $pkg 失败"
    elif command -v yum >/dev/null 2>&1; then
        yum -y install "$pkg" || exiterr "安装 $pkg 失败"
    else
        exiterr "未找到受支持的包管理器 (apt-get/yum)，请手动安装 $pkg"
    fi
}

reload_nginx() {
    nginx -t || exiterr "Nginx 配置校验失败，请检查配置文件"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart nginx
    else
        service nginx restart
    fi
}

upgrade_nginx_to_target() {
    local nginx_bin
    nginx_bin=$(command -v nginx)
    [ -x "$nginx_bin" ] || exiterr "未找到 nginx 可执行文件"

    local current_ver
    current_ver=$($nginx_bin -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)

    if [[ "$current_ver" == "$TARGET_NGINX_VER" ]]; then
        echo "当前 Nginx 已是目标版本 ${TARGET_NGINX_VER}，跳过编译升级。"
        return 0
    fi

    echo "=== 检测到 Nginx 版本为 ${current_ver:-未知}，开始编译升级至 ${TARGET_NGINX_VER} ==="
    local build_dir="/tmp/nginx_build_${TARGET_NGINX_VER}"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    local backup_conf="/root/nginx_conf_backup_${timestamp}"
    local backup_bin="${nginx_bin}.bak.${timestamp}"
    local use_static_openssl=0

    # 1. 备份现有配置与二进制文件
    if [ -d "/etc/nginx" ]; then
        cp -a /etc/nginx "$backup_conf"
        echo "配置已备份至: $backup_conf"
    fi
    cp -a "$nginx_bin" "$backup_bin"
    echo "旧程序已备份至: $backup_bin"

    # 2. 安装编译依赖
    if command -v apt-get >/dev/null 2>&1; then
        fix_debian11_sources
        apt-get update || true
        apt-get install -y build-essential curl zlib1g-dev || exiterr "安装基础编译依赖失败"
        apt-get install -y libpcre2-dev || apt-get install -y libpcre3-dev || exiterr "安装 PCRE 开发库失败"
        if ! apt-get install -y libssl-dev; then
            echo "警告: 系统 libssl-dev 安装失败，将自动采用静态编译 OpenSSL ${OPENSSL_VER}..."
            use_static_openssl=1
        fi
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc gcc-c++ make curl pcre-devel zlib-devel openssl-devel || exiterr "安装编译依赖失败"
    fi

    # 3. 提取并清理当前编译参数
    local raw_args clean_args final_args
    raw_args=$($nginx_bin -V 2>&1 | grep "configure arguments:" | sed 's/configure arguments://')
    clean_args=$(echo "$raw_args" | sed -E 's/--add-(dynamic-)?module=[^ ]+//g' | sed -E 's/--with-[^ ]+=dynamic//g')
    final_args="$clean_args --with-http_ssl_module --with-http_v2_module --with-stream --with-stream_ssl_module"

    # 4. 下载并编译 Nginx
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    (
        cd "$build_dir" || exit 1
        curl -fSLO "https://nginx.org/download/nginx-${TARGET_NGINX_VER}.tar.gz" || exit 1
        tar -zxf "nginx-${TARGET_NGINX_VER}.tar.gz" || exit 1

        if [ "$use_static_openssl" -eq 1 ]; then
            echo "正在下载 OpenSSL ${OPENSSL_VER} 源码..."
            curl -fSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" || exit 1
            tar -zxf "openssl-${OPENSSL_VER}.tar.gz" || exit 1
            final_args="$final_args --with-openssl=${build_dir}/openssl-${OPENSSL_VER}"
        fi

        cd "nginx-${TARGET_NGINX_VER}" || exit 1
        eval ./configure $final_args || exit 1
        make -j"$(nproc)" || exit 1
    ) || exiterr "Nginx ${TARGET_NGINX_VER} 编译失败"

    # 5. 修正旧版动态模块加载与 SSL 语法
    if [ -f "/etc/nginx/nginx.conf" ]; then
        sed -i 's/^\(\s*\)include \/etc\/nginx\/modules-enabled\/\*\.conf;/\1# include \/etc\/nginx\/modules-enabled\/*.conf;/g' /etc/nginx/nginx.conf
    fi

    for dir in /etc/nginx/conf.d /etc/nginx/sites-enabled; do
        [ -d "$dir" ] || continue
        for conf in "$dir"/*; do
            [ -f "$conf" ] || continue
            sed -i 's/^\(\s*\)ssl on;/\1# ssl on;/g' "$conf"
            sed -i -E '/^\s*#/! { /listen\s+([^;]*:)?443\b/ { /\bssl\b/! s/(listen\s+([^;]*:)?443)\b/\1 ssl/ } }' "$conf"
        done
    done

    # 6. 替换二进制文件并校验（失败自动回滚）
    systemctl stop nginx 2>/dev/null || service nginx stop 2>/dev/null || true
    cp "${build_dir}/nginx-${TARGET_NGINX_VER}/objs/nginx" "$nginx_bin"
    chmod +x "$nginx_bin"

    if ! "$nginx_bin" -t; then
        echo "错误: nginx -t 校验失败，正在自动回滚程序和配置..."
        cp -a "$backup_bin" "$nginx_bin"
        if [ -d "$backup_conf" ]; then
            rm -rf /etc/nginx && cp -a "$backup_conf" /etc/nginx
        fi
        systemctl start nginx 2>/dev/null || service nginx start 2>/dev/null || true
        exiterr "Nginx 升级校验失败，已回滚到旧版本"
    fi

    systemctl start nginx 2>/dev/null || service nginx start 2>/dev/null || true

    # 7. 锁定 APT 版本并清理临时文件
    if command -v apt-mark >/dev/null 2>&1; then
        dpkg -l 'nginx*' 2>/dev/null | awk '/^ii/{print $2}' | xargs -r apt-mark hold
    fi
    rm -rf "$build_dir"
    echo "=== Nginx 已成功升级至 $($nginx_bin -v 2>&1) ==="
}

echo "=======================Let's Encrypt环境准备======================================="
if command -v python3 >/dev/null 2>&1; then
    echo 'python3 环境就绪...'
    python_command=python3
else
    echo 'python3 环境不存在，即将开始自动安装...'
    install_pkg python3
    python_command=python3
fi

if command -v openssl >/dev/null 2>&1; then
    echo 'openssl 环境就绪...'
else
    echo 'openssl 不存在，准备安装...'
    install_pkg openssl
fi

if command -v wget >/dev/null 2>&1; then
    echo 'wget 环境就绪...'
else
    echo 'wget 不存在，准备安装...'
    install_pkg wget
fi

if command -v nginx >/dev/null 2>&1; then
    echo 'nginx 已安装，检查版本...'
    upgrade_nginx_to_target
else
    echo "nginx 环境不存在，是否需要自动安装并升级至 ${TARGET_NGINX_VER}？"
    read -p "是否需要安装(y/n)? > " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        install_pkg nginx
        upgrade_nginx_to_target
    else
        exit 0
    fi
fi

echo "==========================环境准备完成==========================="
echo "开始配置"
echo "1、域名配置，请确保你的域名已解析到本机"
echo "请输入域名（多个请用空格隔开）：按回车结束（例：www.baidu.com）"
read -p "> " web_domains
domain_length=0
sign_domain_str=''
web_first_domain=$(echo "$web_domains" | tr -s '[:blank:]' | cut -d ' ' -f 1)
nginx_web_config_file="${web_first_domain}.conf"

for web_domain in ${web_domains}; do
    sign_domain_str="${sign_domain_str}DNS:${web_domain},"
    domain_length=$((domain_length + 1))
done
sign_domain_str=${sign_domain_str%,}
echo "$sign_domain_str"

echo "2、站点绝对路径配置，如果未输入或者输入非绝对路径，就默认使用域名为目录配置到 /certs 目录下"
mkdir -p /certs
read -p "> " web_dir
if [[ -z "$web_dir" || ! "$web_dir" == /* ]]; then
    web_dir="/certs/${web_first_domain}"
fi

echo "3、nginx路径配置，如果你的默认路径是 /etc/nginx，请直接回车"
read -p "> " nginx_config_dir
if [[ -z "$nginx_config_dir" ]]; then
    nginx_config_dir="/etc/nginx"
fi

echo -e "\n"
cat << EOF
确认配置

网站根目录: $web_dir
域名: $web_domains
nginx配置文件路径: $nginx_config_dir

请输入1或2
1):确认
2):退出
EOF
read -p "> " confirm
if [[ "$confirm" -eq 2 ]]; then
    exit 0
fi

echo "===========================自动化配置开始================================="
mkdir -p "${web_dir}/certificate/challenges"
chmod -R 755 "${web_dir}/certificate"
web_first_parent_dir="/$(echo "$web_dir" | cut -d "/" -f2)"
find "$web_first_parent_dir" -type d -exec chmod o+x {} \; 2>/dev/null || true

cd "${web_dir}/certificate" || exiterr "无法进入目录 ${web_dir}/certificate"
echo "Create a Let's Encrypt account private key"
openssl genrsa 4096 > account.key
echo "Generate a domain private key"
openssl genrsa 4096 > domain.key

if [[ $domain_length -gt 1 ]]; then
    openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN \
        -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=$sign_domain_str")) > domain.csr || \
    openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN \
        -config <(cat /etc/pki/tls/openssl.cnf <(printf "[SAN]\nsubjectAltName=$sign_domain_str")) > domain.csr
else
    openssl req -new -sha256 -key domain.key -subj "/CN=$web_first_domain" > domain.csr
fi

mkdir -p "${nginx_config_dir}/conf.d"
cat > "${nginx_config_dir}/conf.d/${nginx_web_config_file}" <<EOF
server {
    listen 80;
    server_name $web_domains;
    location /.well-known/acme-challenge/ {
        alias $web_dir/certificate/challenges/;
        try_files \$uri =404;
    }
}
EOF

reload_nginx

wget -q --no-check-certificate https://cdn.jsdelivr.net/gh/diafygi/acme-tiny@master/acme_tiny.py -O acme_tiny.py || \
    exiterr "下载 acme_tiny.py 失败"

$python_command acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir "$web_dir/certificate/challenges" > ./signed.crt || \
    exiterr "证书申请失败，请检查域名解析和 80 端口是否正常访问"

cp ./signed.crt ./chained.pem

cat > "${nginx_config_dir}/conf.d/${nginx_web_config_file}" <<EOF
server {
    listen 80;
    server_name $web_domains;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name $web_domains;
    root $web_dir;
    index index.html index.htm index.php;

    ssl_certificate $web_dir/certificate/chained.pem;
    ssl_certificate_key $web_dir/certificate/domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:50m;
    ssl_prefer_server_ciphers off;

    location /.well-known/acme-challenge/ {
        alias $web_dir/certificate/challenges/;
        try_files \$uri =404;
    }

    location /download {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }

    # 如果是配置代理请放开以下注释即可
    #location / {
    #    proxy_pass http://120.80.99.120:20000/;
    #    proxy_redirect     off;
    #    proxy_hide_header  Vary;
    #    proxy_set_header   Accept-Encoding '';
    #    proxy_set_header   Host   \$host;
    #    proxy_set_header   Referer \$http_referer;
    #    proxy_set_header   Cookie \$http_cookie;
    #    proxy_set_header   X-Real-IP  \$remote_addr;
    #    proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
    #}
}
EOF

if [[ ! -f "$web_dir/index.html" ]]; then
cat > "$web_dir/index.html" << EOF
generate https website successfully<br/>
this is the index.html of $web_first_domain <br/>
you can visit this page from $web_domains
EOF
fi

current_user="${SUDO_USER:-$(whoami)}"
current_user_group=$(id -gn "$current_user")
chown -R "${current_user}:${current_user_group}" "$web_dir"
chown "${current_user}:${current_user_group}" "${nginx_config_dir}/conf.d/${nginx_web_config_file}"
chmod -R 755 "$web_dir"

reload_nginx

echo -e "\n\n"
cat << EOF
generate https website successfully
your website directory is $web_dir
your nginx config file is $nginx_config_dir/conf.d/$nginx_web_config_file
you can visit your website through these domains:
EOF
for web_domain in ${web_domains}; do
    echo "https://${web_domain}"
done

cat > "$web_dir/certificate/renew_cert.bash" <<EOF
#!/bin/bash
set -e
cd "$web_dir/certificate"
wget -q --no-check-certificate https://cdn.jsdelivr.net/gh/diafygi/acme-tiny@master/acme_tiny.py -O acme_tiny.py
$python_command ./acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir "$web_dir/certificate/challenges/" > /tmp/signed_${web_first_domain}.crt
mv /tmp/signed_${web_first_domain}.crt "$web_dir/certificate/chained.pem"
nginx -t && (systemctl reload nginx || service nginx reload)
EOF
chmod +x "$web_dir/certificate/renew_cert.bash"

echo "Let's Encrypt 证书有效期定时任务配置"
if command -v crontab >/dev/null 2>&1; then
    echo 'crontab 已安装'
else
    echo 'crontab 未安装，将为您自动安装...'
    install_pkg cron
fi

CRON_JOB="1 1 1 * * root bash $web_dir/certificate/renew_cert.bash >> /var/log/renew_cert.log 2>> /var/log/renew_cert_error.log"
if ! grep -Fq "$web_dir/certificate/renew_cert.bash" /etc/crontab; then
    echo "$CRON_JOB" >> /etc/crontab
    echo "证书续期定时器添加成功"
else
    echo "证书续期定时器已存在，跳过重复添加"
fi

read -p 'press any key to quit'
exit 0
