# Описание переменных WAIDPS

## Глобальные переменные

### Сетевые интерфейсы и MAC-адреса
- `IFace` - Текущий сетевой интерфейс
- `MyMAC` - MAC-адрес текущего интерфейса
- `ProcessID` - ID текущего процесса
- `ProcessList` - Список активных процессов

### Списки для хранения данных точек доступа
- `BSSIDList` - Список MAC-адресов точек доступа
- `ESSIDList` - Список имен сетей (SSID)
- `ChannelList` - Список каналов точек доступа
- `EncTypeList` - Список типов шифрования
- `SignalList` - Уровни сигнала точек доступа

### Списки для хранения данных клиентов
- `ClientMACList` - MAC-адреса клиентов
- `ClientDataList` - Данные о клиентах
- `ClientAPList` - Связи клиентов с точками доступа
- `ClientAPDataList` - Данные о связях клиент-AP
- `ProbeReqList` - Список probe-запросов
- `ProbeRespList` - Список ответов на probe-запросы

### WPS данные
- `WPSList` - Список точек доступа с WPS
- `WPSDataList` - Данные о WPS точках доступа
- `WPSFailList` - Неудачные попытки WPS

### Белые списки и фильтры
- `WhiteList` - Белый список MAC-адресов
- `MonitorList` - Список отслеживаемых устройств
- `FilterList` - Список фильтров

## Переменные пакетного анализа

### MAC-адреса в пакетах
- `MAC_TA` - Transmitter Address
- `MAC_RA` - Receiver Address
- `MAC_SA` - Source Address
- `MAC_DA` - Destination Address
- `MAC_BSSID` - BSSID точки доступа

### Типы устройств
- `SRC_TYPE` - Тип источника
- `DST_TYPE` - Тип получателя
- `SRC_MAC` - MAC-адрес источника
- `DST_MAC` - MAC-адрес получателя
- `SRC_MACLoc` - Расположение источника
- `DST_MACLoc` - Расположение получателя

### Данные фреймов
- `frame_type` - Тип фрейма (management, control, data)
- `frame_subtype` - Подтип фрейма (beacon, probe, auth, etc.)
- `frame_protected` - Защищенность фрейма
- `frame_retry` - Флаг повтора
- `frame_moredata` - Флаг дополнительных данных

### Параметры сети
- `ESSID` - Имя сети
- `BSSID` - MAC-адрес точки доступа
- `Channel` - Канал
- `Frequency` - Частота
- `Signal` - Уровень сигнала
- `Quality` - Качество сигнала
- `Encryption` - Тип шифрования
- `Cipher` - Используемый шифр
- `Authentication` - Тип аутентификации

### WPS параметры
- `WPS_Version` - Версия WPS
- `WPS_Config` - Конфигурация WPS
- `WPS_State` - Состояние WPS
- `WPS_Locked` - Блокировка WPS

## Переменные анализа атак

### Счетчики пакетов
- `deauth_counter` - Счетчик пакетов деаутентификации
- `auth_counter` - Счетчик пакетов аутентификации
- `probe_counter` - Счетчик probe-запросов
- `beacon_counter` - Счетчик beacon-фреймов

### Временные метки
- `last_deauth_time` - Время последнего пакета деаутентификации
- `last_auth_time` - Время последней аутентификации
- `last_probe_time` - Время последнего probe-запроса
- `last_beacon_time` - Время последнего beacon-фрейма

### Пороговые значения
- `deauth_threshold` - Порог для атаки деаутентификации
- `auth_threshold` - Порог для флуда аутентификацией
- `probe_threshold` - Порог для флуда probe-запросами
- `beacon_threshold` - Порог для beacon флуда

## Файловая система

### Директории
- `DB/` - Директория базы данных
  * `crack.csv` - Данные о взломанных сетях
  * `client.csv` - Данные о клиентах
  * `wps.csv` - Данные о WPS
  * `white.lst` - Белый список
- `Dump/` - Директория дампов
  * `*.cap` - Захваченные пакеты
  * `*.csv` - Данные airodump-ng
- `Captured/` - Захваченные handshakes
  * `*.cap` - WPA handshakes
  * `*.xor` - WEP ключевые потоки

### Временные файлы
- `*.tmp` - Временные файлы
- `*.pid` - Файлы процессов
- `*.log` - Лог файлы

## Цветовое оформление

### Цвета текста
- `fcolor.CReset` - Сброс цвета
- `fcolor.BRed` - Яркий красный
- `fcolor.BGreen` - Яркий зеленый
- `fcolor.BYellow` - Яркий желтый
- `fcolor.BBlue` - Яркий синий
- `fcolor.BPurple` - Яркий фиолетовый
- `fcolor.BCyan` - Яркий голубой
- `fcolor.BWhite` - Яркий белый

### Цвета фона
- `fcolor.BGBlack` - Черный фон
- `fcolor.BGRed` - Красный фон
- `fcolor.BGGreen` - Зеленый фон
- `fcolor.BGYellow` - Желтый фон
- `fcolor.BGBlue` - Синий фон
- `fcolor.BGPurple` - Фиолетовый фон
- `fcolor.BGCyan` - Голубой фон
- `fcolor.BGWhite` - Белый фон

## Статусы и флаги

### Состояния программы
- `RUNNING` - Программа запущена
- `PAUSED` - Программа приостановлена
- `STOPPED` - Программа остановлена
- `MONITORING` - Режим мониторинга
- `ATTACKING` - Режим атаки
- `ANALYZING` - Режим анализа

### Флаги операций
- `DEAUTH_ACTIVE` - Активна деаутентификация
- `WPS_ACTIVE` - Активна атака WPS
- `CAPTURE_ACTIVE` - Активен захват пакетов
- `INJECTION_ACTIVE` - Активна инъекция пакетов
- `SCAN_ACTIVE` - Активно сканирование

### Статусы операций
- `SUCCESS` - Успешное выполнение
- `FAILED` - Ошибка выполнения
- `IN_PROGRESS` - В процессе
- `WAITING` - Ожидание
- `TIMEOUT` - Превышение времени ожидания

## Конфигурационные параметры

### Таймауты
- `SCAN_TIMEOUT` - Таймаут сканирования
- `CAPTURE_TIMEOUT` - Таймаут захвата
- `ATTACK_TIMEOUT` - Таймаут атаки
- `RESPONSE_TIMEOUT` - Таймаут ответа

### Интервалы
- `SCAN_INTERVAL` - Интервал сканирования
- `UPDATE_INTERVAL` - Интервал обновления
- `CLEANUP_INTERVAL` - Интервал очистки
- `SAVE_INTERVAL` - Интервал сохранения

### Лимиты
- `MAX_CLIENTS` - Максимум клиентов
- `MAX_APS` - Максимум точек доступа
- `MAX_RETRIES` - Максимум повторов
- `MAX_PACKETS` - Максимум пакетов
