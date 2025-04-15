#!/bin/bash

echo "Setting up Network Detection Tool..."

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Установка системных зависимостей
apt install -y python3-venv python3-full python3-pip wireless-tools \
    libxcb-cursor0 libxcb1 libxcb-glx0 libxcb-icccm4 \
    libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render0 \
    libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 \
    libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 \
    qt6-base-dev

# Создание виртуального окружения
VENV_PATH="/opt/network-detection/venv"
mkdir -p /opt/network-detection
python3 -m venv $VENV_PATH

# Активация виртуального окружения и установка зависимостей
source $VENV_PATH/bin/activate
pip install scapy PySide6

# Копирование файлов программы
INSTALL_PATH="/opt/network-detection"
cp ./*.py $INSTALL_PATH/

# Создание скрипта запуска
cat > /usr/local/bin/network-detection << 'EOF'
#!/bin/bash
source /opt/network-detection/venv/bin/activate
cd /opt/network-detection
export QT_DEBUG_PLUGINS=1
exec sudo /opt/network-detection/venv/bin/python3 main.py
EOF

# Установка прав
chmod +x /usr/local/bin/network-detection
chmod -R 755 /opt/network-detection

echo "Installation complete!"
echo "To run the program, use command: sudo network-detection"
