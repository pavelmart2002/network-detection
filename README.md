# Network Detection Tool

Инструмент для мониторинга и анализа WiFi сетей, способный обнаруживать различные типы атак на беспроводные сети.

## Возможности

- Мониторинг WiFi трафика в реальном времени
- Обнаружение атак деаутентификации
- Анализ подозрительной активности в сети
- Графический интерфейс на базе PySide6 (Qt)

## Установка

### Linux (Ubuntu/Debian)

```bash
# Клонирование репозитория
git clone https://github.com/pavelmart2002/network-detection.git
cd network-detection

# Установка
sudo ./setup_linux.sh

# Запуск
sudo network-detection
```

### Windows

1. Установите [Npcap](https://npcap.com/)
2. Установите зависимости:
```bash
pip install scapy PySide6
```
3. Запустите программу от имени администратора:
```bash
python main.py
```

### Установка на Raspberry Pi

1. Установите git и Python 3:
   ```bash
   sudo apt update
   sudo apt install git python3 python3-pip python3-venv
   ```
2. Клонируйте репозиторий и перейдите в папку:
   ```bash
   git clone https://github.com/pavelmart2002/network-detection.git
   cd network-detection/detection
   ```
3. Запустите установку:
   ```bash
   sudo bash setup_linux.sh
   ```
4. Запустите программу:
   ```bash
   sudo network-detection
   ```

## Быстрое обновление

Чтобы получить последнюю версию на Raspberry Pi:
```bash
cd ~/network-detection
git pull
sudo bash setup_linux.sh
```

## Важно
- Для захвата WiFi-пакетов нужен адаптер с поддержкой режима мониторинга.
- Запускать программу нужно с правами root (`sudo`).
- Для Windows поддержка ограничена.

## Требования

- Python 3.8+
- Scapy
- PySide6
- Беспроводной адаптер с поддержкой режима мониторинга
- Права администратора/root

## Лицензия

MIT License

## Автор

Pavel Mart (@pavelmart2002)
