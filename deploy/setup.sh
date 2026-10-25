#!/usr/bin/env bash
# Встановлює сайт бюджету на VPS з Ubuntu/Debian.
# Запуск із папки репозиторію:  sudo bash deploy/setup.sh [домен]
# Без домену сайт буде доступний за IP через http, з доменом ще й отримає HTTPS від Let's Encrypt.
set -euo pipefail

DOMAIN="${1:-}"
ROOT=/var/www/czeresniowski
SRC="$(cd "$(dirname "$0")/.." && pwd)/index.html"

[ "$(id -u)" -eq 0 ] || { echo "Запустіть через sudo"; exit 1; }
[ -f "$SRC" ] || { echo "Не знайдено $SRC"; exit 1; }

apt-get update -y
apt-get install -y nginx
[ -n "$DOMAIN" ] && apt-get install -y certbot python3-certbot-nginx

install -d "$ROOT"
install -m 644 "$SRC" "$ROOT/index.html"

cat > /etc/nginx/sites-available/czeresniowski <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN:-_};
    root $ROOT;
    index index.html;

    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Referrer-Policy no-referrer;

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

if [ -n "$DOMAIN" ]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect
fi

echo "Готово: http${DOMAIN:+s}://${DOMAIN:-$(hostname -I | awk '{print $1}')}/"
