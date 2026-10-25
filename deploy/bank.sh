#!/usr/bin/env bash
# Зберігає ключ застосунку Enable Banking на сервері.
# Запуск:  sudo bash deploy/bank.sh <Application ID> <шлях до .pem>
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Запустіть через sudo"; exit 1; }
[ $# -eq 2 ] && [ -f "$2" ] || { echo "Використання: sudo bash deploy/bank.sh <Application ID> <файл.pem>"; exit 1; }
DATA=/var/lib/czeresniowski
install -o czeres -g czeres -m 600 "$2" "$DATA/upload.pem"
sudo -u czeres DATA_DIR="$DATA" python3 /opt/czeresniowski/server.py --set-bank "$1" "$DATA/upload.pem"
rm -f "$DATA/upload.pem" "$2"
systemctl restart czeresniowski
echo "Готово. Відкрийте сайт і натисніть «Підключити банк»."
