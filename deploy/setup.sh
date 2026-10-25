#!/usr/bin/env bash
# Встановлює або оновлює сайт бюджету на VPS з Ubuntu/Debian.
# Запуск із папки репозиторію:  sudo bash deploy/setup.sh [домен]
# Без домену береться безкоштовна адреса <ip-через-дефіси>.sslip.io, щоб отримати HTTPS від Let's Encrypt.
# Змінити пароль пізніше:  sudo -u czeres DATA_DIR=/var/lib/czeresniowski python3 /opt/czeresniowski/server.py --set-password
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ROOT=/var/www/czeresniowski
APP=/opt/czeresniowski
DATA=/var/lib/czeresniowski
IP="$(hostname -I | awk '{print $1}')"
DOMAIN="${1:-${IP//./-}.sslip.io}"

[ "$(id -u)" -eq 0 ] || { echo "Запустіть через sudo"; exit 1; }

apt-get update -y
apt-get install -y nginx python3 certbot python3-certbot-nginx

# сайт і сервер даних
install -d "$ROOT" "$APP"
install -m 644 "$REPO/index.html" "$ROOT/index.html"
install -m 755 "$REPO/server/server.py" "$APP/server.py"
id czeres >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin czeres
install -d -o czeres -g czeres -m 700 "$DATA"

if [ ! -f "$DATA/config.json" ]; then
  echo "Придумайте пароль для входу на сайт."
  sudo -u czeres DATA_DIR="$DATA" python3 "$APP/server.py" --set-password
fi

cat > /etc/systemd/system/czeresniowski.service <<UNIT
[Unit]
Description=Czereśniowski budget data server
After=network.target

[Service]
User=czeres
Environment=DATA_DIR=$DATA
ExecStart=/usr/bin/python3 $APP/server.py
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable czeresniowski
systemctl restart czeresniowski

# nginx: якщо сертифікат уже є, certbot сам відновить у конфігу блок HTTPS
cat > /etc/nginx/sites-available/czeresniowski <<NGINX
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN _;
    root $ROOT;
    index index.html;
    client_max_body_size 10m;
    server_tokens off;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;

    location /api/ {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    location / { try_files \$uri /index.html; }
}
NGINX
ln -sf /etc/nginx/sites-available/czeresniowski /etc/nginx/sites-enabled/czeresniowski
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

if command -v ufw >/dev/null && ufw status | grep -q active; then
  ufw allow 'Nginx Full'
fi

if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect; then
  # хто відкриє сайт просто за IP, теж потрапить на захищену адресу
  cat > /etc/nginx/sites-available/czeresniowski-ip <<NGINX
server {
    listen 80;
    server_name $IP;
    return 301 https://$DOMAIN\$request_uri;
}
NGINX
  ln -sf /etc/nginx/sites-available/czeresniowski-ip /etc/nginx/sites-enabled/czeresniowski-ip
  nginx -t && systemctl reload nginx
  echo "Готово: https://$DOMAIN/"
else
  echo "Не вдалося отримати сертифікат HTTPS. Сайт працює без шифрування: http://$IP/"
fi
