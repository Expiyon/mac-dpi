#!/bin/bash
# Cift tikla -> Terminal acilir, proxy calisir, sistem proxy'si otomatik ayarlanir.
# Bu pencereyi kapatinca ya da Ctrl+C yapinca sistem proxy'si eski haline doner.

cd "$(dirname "$0")" || exit 1

# Guvenlik agi: python restore etse bile bir kez daha dene.
trap 'python3 dpi.py restore >/dev/null 2>&1' EXIT

clear
echo "======================================================"
echo "  DPI atlatma proxy'si baslatiliyor"
echo "  Durdurmak: bu pencereyi kapat veya Ctrl+C"
echo "======================================================"
echo

python3 dpi.py run "$@"

echo
echo "Proxy durdu, sistem ayarlari geri yuklendi. Pencereyi kapatabilirsiniz."
