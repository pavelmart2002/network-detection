{{ ... }}

## Функция OptDisplayLogs (продолжение)

```python
        print center_text(HeaderLine)
```
- Центрирование и вывод заголовка меню
- Использование ранее определенного HeaderLine

```python
        DrawLine("-",fcolor.CReset,"")
```
- Рисование нижней разделительной линии
- Сброс цветового форматирования

```python
        print "1. Normal Display Mode"
        print "2. Minimal Display Mode"
        print "3. Return to Previous Menu"
```
- Вывод пунктов меню
- Три режима отображения логов
- Опция возврата в предыдущее меню

## Функция AddToList

```python
def AddToList(sStr,sList):
    if str(sList).find(sStr)==-1:
        sList.append(sStr)
```
- Функция добавления элемента в список
- sStr: строка для добавления
- sList: целевой список
- Проверка отсутствия строки в списке
- Добавление только если строки нет

## Функция OptAuditing

```python
def OptAuditing(HeaderLine):
    global BSSIDList
    global ESSIDList
    global ChannelList
    global EncTypeList
    global AuthTypeList
    global StationList
    global StationMacList
    global ProbeList
```
- Функция аудита WiFi сетей
- Объявление глобальных списков для хранения данных:
  - BSSIDList: MAC-адреса точек доступа
  - ESSIDList: имена сетей
  - ChannelList: каналы
  - EncTypeList: типы шифрования
  - AuthTypeList: типы аутентификации
  - StationList: подключенные устройства
  - StationMacList: MAC-адреса устройств
  - ProbeList: пробные запросы

```python
    if os.path.exists("DB/"):
        shutil.rmtree("DB/")
    os.makedirs("DB/")
```
- Очистка и создание директории для базы данных
- Удаление старой директории если существует
- Создание новой директории

## Функция AddClientMAC

```python
def AddClientMAC(CLMAC,SDATA):
    global ClientMACList
    global ClientDataList
```
- Функция добавления MAC-адреса клиента
- CLMAC: MAC-адрес клиента
- SDATA: дополнительные данные

```python
    if str(ClientMACList).find(CLMAC)==-1:
        ClientMACList.append(CLMAC)
        ClientDataList.append(SDATA)
```
- Проверка отсутствия MAC-адреса в списке
- Добавление MAC-адреса и данных в соответствующие списки

## Функция ClearClientAPList

```python
def ClearClientAPList(cmd):
    global ClientAPList
    global ClientAPDataList
```
- Функция очистки списка клиентов и точек доступа
- cmd: команда для очистки

```python
    if cmd=="1":
        ClientAPList = []
        ClientAPDataList = []
```
- Если команда "1", очищаем оба списка
- Создание новых пустых списков

## Функция PreLoadMonFile

```python
def PreLoadMonFile():
    global MonitorCapFile
```
- Функция предварительной загрузки файла мониторинга
- Использование глобальной переменной для имени файла

```python
    if os.path.exists("./LiveMon/"):
        shutil.rmtree("./LiveMon/")
    os.makedirs("./LiveMon/")
```
- Подготовка директории для живого мониторинга
- Удаление старой директории
- Создание новой директории

## Функция LogMonDetail

```python
def LogMonDetail(DataStr):
    global MonitorCapFile
```
- Функция логирования деталей мониторинга
- DataStr: данные для логирования
- Использование глобального файла для записи

```python
    f = open(MonitorCapFile,"a")
    f.write(DataStr + "\n")
    f.close()
```
- Открытие файла в режиме добавления ("a")
- Запись данных с новой строкой
- Закрытие файла

## Функция LogMonFile

```python
def LogMonFile(DataStr):
    global MonitorCurrentFile
```
- Функция логирования в файл мониторинга
- DataStr: строка данных для записи
- Использование текущего файла мониторинга

```python
    try:
        f = open(MonitorCurrentFile,"a")
        f.write(DataStr + "\n")
        f.close()
    except:
        printd("Error writing to monitoring file!")
```
- Попытка записи в файл
- Обработка возможных ошибок
- Вывод сообщения об ошибке при неудаче

## Функция MonitorAccessPoint (основная часть)

```python
def MonitorAccessPoint(TargetMAC,Auto):
    global BSSIDList
    global ESSIDList
    global ChannelList
```
- Основная функция мониторинга точки доступа
- TargetMAC: целевой MAC-адрес
- Auto: флаг автоматического режима
- Использование глобальных списков для данных

```python
    if not os.path.exists("./LiveMon/"):
        os.makedirs("./LiveMon/")
```
- Проверка и создание директории для живого мониторинга
- Создание директории если не существует

[Продолжение следует...]

## Функции обработки сетевых пакетов

### Функция DisplayCapturedPacket

```python
def DisplayCapturedPacket(PK_File):
    global PacketCount
    global LastPacket
```
- Функция для отображения захваченных пакетов
- Использует глобальные счетчики пакетов
- PK_File: файл с захваченными пакетами

### Функция Hex2Chr

```python
def Hex2Chr(sHex):
    return chr(int(sHex.replace(' ',''), 16))
```
- Преобразование шестнадцатеричного значения в символ
- Удаление пробелов из hex-строки
- Конвертация в целое число с основанием 16
- Преобразование числа в символ

### Функция AddHexColon

```python
def AddHexColon(sHex):
    return ':'.join(sHex[i:i+2] for i in range(0, len(sHex), 2))
```
- Добавление двоеточий между парами hex-символов
- Используется для форматирования MAC-адресов
- Разбивает строку на пары символов
- Соединяет пары двоеточиями

### Функция ConvertHex

```python
def ConvertHex(sHex):
    global IMPORT_ERRMSG
```
- Функция конвертации hex-данных
- Обработка различных форматов hex-строк
- Использует глобальную переменную для ошибок

### Функция CheckCrackingStatus

```python
def CheckCrackingStatus(TargetMAC):
    global CrackList
```
- Проверка статуса взлома для MAC-адреса
- TargetMAC: проверяемый MAC-адрес
- Использует глобальный список взломанных устройств

### Функция GetFileMaxLength

```python
def GetFileMaxLength(FFILE):
    MaxLen = 0
    try:
        f = open(FFILE,"r")
        for line in f:
            MaxLen += 1
        f.close()
    except:
        MaxLen = -1
    return MaxLen
```
- Подсчет количества строк в файле
- FFILE: путь к файлу
- Обработка ошибок при открытии файла
- Возвращает -1 при ошибке

### Функция DisplayCapturedFile

```python
def DisplayCapturedFile(HS_File):
    DrawLine("-",fcolor.CReset,"")
    print center_text("Captured Handshake Detail")
    DrawLine("-",fcolor.CReset,"")
```
- Отображение деталей захваченного рукопожатия
- HS_File: файл с рукопожатием
- Форматированный вывод с разделителями

### Функция CrackWPAKey

```python
def CrackWPAKey(HS_File,Auto):
    global ProcessID
```
- Функция для взлома WPA ключа
- HS_File: файл с рукопожатием
- Auto: флаг автоматического режима
- Использует внешние инструменты для взлома

### Функция AttackWPAProc

```python
def AttackWPAProc(TargetMAC,TargetChannel,ClientList,Auto):
    global ProcessID
    global AttackMethod
```
- Процедура атаки на WPA
- Параметры:
  - TargetMAC: целевой MAC-адрес
  - TargetChannel: канал WiFi
  - ClientList: список клиентов
  - Auto: автоматический режим
- Управление процессом атаки

[Продолжение следует...]

## Функции анализа следующих функций

### Функция ManualCheckHandShake

```python
def ManualCheckHandShake(capfile):
    global ProcessID
```
- Ручная проверка захваченного рукопожатия
- capfile: файл с захваченными пакетами
- Использует глобальный ID процесса

```python
    if os.path.exists(capfile):
        try:
            cmd = "aircrack-ng " + capfile
            ProcessID = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```
- Проверка существования файла
- Запуск aircrack-ng для анализа файла
- Перехват вывода команды

### Функция DisplayComplete

```python
def DisplayComplete(TStart):
    DrawLine("=",fcolor.SWhite,"")
    print center_text(fcolor.BWhite + "Completed - " + str(datetime.datetime.now() - TStart) + fcolor.CReset)
    DrawLine("=",fcolor.SWhite,"")
```
- Отображение завершения операции
- TStart: время начала операции
- Вычисление затраченного времени
- Форматированный вывод с разделителями

### Функция Find2MACIndex

```python
def Find2MACIndex(MACAddr,ListToFind):
    x = 0
    ReturnIndex = -1
    while x < len(ListToFind):
        if str(ListToFind[x]).find(MACAddr)!=-1:
            ReturnIndex = x
            break
        x += 1
    return ReturnIndex
```
- Поиск MAC-адреса в списке
- MACAddr: искомый MAC-адрес
- ListToFind: список для поиска
- Возвращает индекс найденного элемента или -1

### Функция CheckHandshake

```python
def CheckHandshake(capfile,TargetMAC,ESSID):
    global ProcessID
    global CrackList
```
- Проверка захваченного рукопожатия
- Параметры:
  - capfile: файл с пакетами
  - TargetMAC: MAC-адрес цели
  - ESSID: имя сети
- Анализ рукопожатия WPA

```python
    if os.path.exists(capfile):
        try:
            cmd = "aircrack-ng " + capfile
            ProcessID = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```
- Проверка файла и запуск aircrack-ng
- Захват вывода для анализа
- Обработка ошибок

### Функция WPSAddOnPara

```python
def WPSAddOnPara(Para,Header):
    ReturnPara = ""
    if Para.find("--pin=")!=-1:
        ReturnPara = Para
    elif Para=="":
        ReturnPara = AskQuestion(Header + "Enter custom parameter : ","")
```
- Обработка параметров WPS
- Para: входной параметр
- Header: заголовок для запроса
- Обработка PIN-кода WPS

### Функция AttackWPSProc

```python
def AttackWPSProc(TargetMAC,TargetChannel,ClientList,Auto):
    global ProcessID
    global AttackMethod
    global WPSLock
```
- Процедура атаки на WPS
- Параметры атаки и статус
- Управление процессом
- Обработка блокировки WPS

```python
    TStartWPS = datetime.datetime.now()
    printc("*","Starting WPS Attack Mode on " + TargetMAC)
```
- Засечка времени начала
- Информирование о начале атаки

### Функция TimerApp

```python
def TimerApp(cmdLine,DelaySeconds,ShowDisplay):
    if ShowDisplay==1:
        printc("*","Starting timer for " + str(DelaySeconds) + " seconds")
```
- Таймер для выполнения команд
- cmdLine: команда для выполнения
- DelaySeconds: задержка в секундах
- ShowDisplay: флаг отображения

```python
    time.sleep(DelaySeconds)
    if ShowDisplay==1:
        printc("+","Timer completed")
```
- Ожидание указанного времени
- Вывод сообщения о завершении

### Функция RearrangeReturn

```python
def RearrangeReturn(sLine):
    global IMPORT_ERRMSG
    ReturnStr = ""
    try:
        ReturnStr = str(sLine.group())
    except:
        ReturnStr = str(sLine)
```
- Обработка возвращаемых строк
- Обработка ошибок преобразования
- Работа с регулярными выражениями

### Функция GetClientFromCSV

```python
def GetClientFromCSV(sFile):
    ReturnClient = []
    if os.path.exists(sFile):
        f = open(sFile,"r")
        for line in f:
            if line.replace(' ','')!="":
                ReturnClient.append(line.replace('\n',''))
        f.close()
```
- Чтение клиентов из CSV файла
- sFile: путь к файлу
- Обработка пустых строк
- Формирование списка клиентов

### Функция RerunCapturedFile

```python
def RerunCapturedFile(TargetMAC,TargetChannel):
    global ProcessID
    global CrackList
```
- Повторный запуск анализа захваченного файла
- TargetMAC: MAC-адрес цели
- TargetChannel: канал WiFi
- Использование глобальных переменных для процесса и списка взломов

```python
    if os.path.exists("Captured/"):
        CapturedList = glob.glob("Captured/*.cap")
```
- Поиск всех .cap файлов в директории
- Использование glob для поиска по маске

### Функция AttackWEPProc

```python
def AttackWEPProc(TargetMAC,TargetChannel,ClientList):
    global ProcessID
    global AttackMethod
    global InjectionStatus
```
- Процедура атаки на WEP шифрование
- Параметры атаки и статус
- Управление инъекцией пакетов

```python
    TStartWEP = datetime.datetime.now()
    printc("*","Starting WEP Attack Mode on " + TargetMAC)
```
- Засечка времени начала
- Информирование о начале атаки

### Функция KillAllProcList

```python
def KillAllProcList():
    global ProcessList
```
- Завершение всех запущенных процессов
- Использование глобального списка процессов

```python
    for proc in ProcessList:
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except:
            pass
```
- Перебор всех процессов
- Отправка сигнала SIGTERM
- Обработка ошибок завершения

### Функция ListCapturedFile

```python
def ListCapturedFile(TargetMAC2):
    DrawLine("-",fcolor.CReset,"")
    print center_text("Captured File Selection")
    DrawLine("-",fcolor.CReset,"")
```
- Отображение списка захваченных файлов
- Форматированный вывод с разделителями
- Центрирование заголовка

### Функция WEPAttackMode

```python
def WEPAttackMode(Mode,FName,ARPFile, ToDisplay):
    global ProcessID
    global InjectionStatus
```
- Режим атаки на WEP
- Mode: тип атаки
- FName: имя файла
- ARPFile: файл ARP-запросов
- ToDisplay: флаг отображения

```python
    if Mode=="1":
        # Fake Authentication
        cmd = "aireplay-ng -1 0 -a " + WBSSID + " -h " + MyMAC + " " + IFace
```
- Выбор режима атаки
- Формирование команды aireplay-ng
- Параметры аутентификации

### Функция CheckWPSLog

```python
def CheckWPSLog(WBSSID):
    WPSReturn = "No"
    if os.path.exists("DB/wps.csv"):
        f = open("DB/wps.csv","r")
```
- Проверка лога WPS
- WBSSID: MAC-адрес точки доступа
- Чтение данных из CSV файла

### Функция DisplayAPDetail

```python
def DisplayAPDetail():
    global BSSIDList
    global ESSIDList
    global ChannelList
```
- Отображение деталей точки доступа
- Использование глобальных списков
- Форматированный вывод информации

```python
    DrawLine("-",fcolor.CReset,"")
    print center_text("Access Point Detail")
    DrawLine("-",fcolor.CReset,"")
```
- Оформление вывода
- Центрирование заголовка
- Разделительные линии

### Функция DisplayARPFileList

```python
def DisplayARPFileList():
    if os.path.exists("./DB/"):
        ARPList = glob.glob("DB/*.arp")
```
- Отображение списка ARP файлов
- Поиск .arp файлов в директории
- Использование glob для поиска

### Функция CheckARPFile

```python
def CheckARPFile(ARPFile):
    ReturnStr = ""
    try:
        f = open(ARPFile,"r")
        ReturnStr = f.readline()
        f.close()
    except:
        ReturnStr = ""
```
- Проверка содержимого ARP файла
- ARPFile: путь к файлу
- Чтение первой строки
- Обработка ошибок чтения

### Функция ShutDownAuditingWindows

```python
def ShutDownAuditingWindows():
    global ProcessID
    try:
        os.kill(ProcessID.pid, signal.SIGTERM)
    except:
        pass
```
- Завершение окон аудита
- Отправка сигнала SIGTERM процессу
- Обработка ошибок завершения

### Функция DisplayCrackDB

```python
def DisplayCrackDB():
    DrawLine("-",fcolor.CReset,"")
    print center_text("Cracked Password Database")
    DrawLine("-",fcolor.CReset,"")
```
- Отображение базы данных взломанных паролей
- Форматированный вывод заголовка
- Использование разделительных линий

```python
    if os.path.exists("DB/crack.csv"):
        f = open("DB/crack.csv","r")
        for line in f:
            if line.replace(' ','')!="":
                crack = line.split(',')
```
- Чтение данных из CSV файла
- Обработка каждой строки
- Разделение данных по запятым
- Пропуск пустых строк

### Функция InputCrackDB

```python
def InputCrackDB():
    global BSSIDList
    global ESSIDList
    global EncTypeList
```
- Ввод данных в базу взломанных паролей
- Использование списков BSSID и ESSID
- Хранение информации о сетях

```python
    HeaderLine = "Add New Cracked Password"
    DrawLine("-",fcolor.CReset,"")
    print center_text(HeaderLine)
    DrawLine("-",fcolor.CReset,"")
```
- Форматирование интерфейса
- Вывод заголовка
- Разделительные линии

### Функция CheckCrackDB

```python
def CheckCrackDB(BSSID):
    CrackReturn = []
    if os.path.exists("DB/crack.csv"):
        f = open("DB/crack.csv","r")
```
- Проверка наличия MAC-адреса в базе
- BSSID: проверяемый MAC-адрес
- Чтение базы данных из файла

### Функция AddCrackDB

```python
def AddCrackDB(BSSID,Enc,EncKey,ESSID,HS_File,WPS,Ignore):
    if not os.path.exists("DB"):
        os.makedirs("DB")
```
- Добавление новой записи в базу
- Параметры:
  - BSSID: MAC-адрес
  - Enc: тип шифрования
  - EncKey: ключ шифрования
  - ESSID: имя сети
  - HS_File: файл рукопожатия
  - WPS: статус WPS
  - Ignore: флаг игнорирования

### Функция Fake_Auth

```python
def Fake_Auth(TargetMAC,FName):
    global ProcessID
    global InjectionStatus
```
- Выполнение фальшивой аутентификации
- TargetMAC: целевой MAC-адрес
- FName: имя файла для сохранения
- Управление статусом инъекции

```python
    printc("*","Starting Fake Authentication with " + TargetMAC)
    cmd = "aireplay-ng -1 0 -a " + TargetMAC + " -h " + MyMAC + " " + IFace
```
- Запуск процесса аутентификации
- Формирование команды aireplay-ng
- Использование MAC-адреса атакующего

### Функция DeauthBroadcast

```python
def DeauthBroadcast(BSSID,IFace,DeauthCt):
    cmd = "aireplay-ng -0 " + str(DeauthCt) + " -a " + BSSID + " " + IFace + " > /dev/null 2>&1 &"
```
- Широковещательная деаутентификация
- BSSID: MAC-адрес точки доступа
- IFace: сетевой интерфейс
- DeauthCt: количество пакетов

### Функция ListClientFound

```python
def ListClientFound():
    global ClientMACList
    global ClientDataList
```
- Отображение найденных клиентов
- Использование глобальных списков
- Вывод информации о клиентах

```python
    DrawLine("-",fcolor.CReset,"")
    print center_text("Client List")
    DrawLine("-",fcolor.CReset,"")
```
- Форматирование вывода
- Заголовок списка клиентов
- Визуальное оформление

### Функция ListClientFoundDB

```python
def ListClientFoundDB():
    if os.path.exists("DB/client.csv"):
        f = open("DB/client.csv","r")
```
- Чтение базы данных клиентов
- Проверка существования файла
- Обработка данных из CSV

### Функция DisplayStationDetail

```python
def DisplayStationDetail():
    DrawLine("-",fcolor.CReset,"")
    print center_text("Station Detail")
    DrawLine("-",fcolor.CReset,"")
```
- Отображение информации о станциях
- Форматированный вывод заголовка
- Визуальное оформление

### Функция DisplayClientAPDetail

```python
def DisplayClientAPDetail():
    global ClientAPList
    global ClientAPDataList
```
- Отображение деталей клиентов AP
- Использование глобальных списков
- Форматированный вывод данных

### Функция AddClientAP

```python
def AddClientAP(APMAC,CLMAC,SDATA):
    global ClientAPList
    global ClientAPDataList
```
- Добавление связи клиент-AP
- Параметры:
  - APMAC: MAC-адрес точки доступа
  - CLMAC: MAC-адрес клиента
  - SDATA: дополнительные данные

```python
    if str(ClientAPList).find(APMAC + "," + CLMAC)==-1:
        ClientAPList.append(APMAC + "," + CLMAC)
        ClientAPDataList.append(SDATA)
```
- Проверка уникальности связи
- Добавление новой записи
- Сохранение дополнительных данных

### Функция ClearClientProbe

```python
def ClearClientProbe(cmd):
    global ClientMACList
    global ClientDataList
```
- Очистка данных о пробных запросах
- cmd: команда для очистки
- Управление глобальными списками

```python
    if cmd=="1":
        ClientMACList = []
        ClientDataList = []
```
- Проверка команды очистки
- Сброс списков в пустое состояние

### Функция LoadWPSLog

```python
def LoadWPSLog():
    global WPSList
    global WPSDataList
    WPSList = []
    WPSDataList = []
```
- Загрузка логов WPS
- Инициализация списков
- Очистка старых данных

```python
    if os.path.exists("DB/wps.csv"):
        f = open("DB/wps.csv","r")
        for line in f:
            if line.replace(' ','')!="":
                wps = line.split(',')
```
- Чтение данных из CSV
- Обработка строк
- Разбор на компоненты

### Функция SaveWPSLog

```python
def SaveWPSLog():
    global WPSList
    global WPSDataList
```
- Сохранение логов WPS
- Работа с глобальными списками
- Запись в файл базы данных

```python
    if not os.path.exists("DB"):
        os.makedirs("DB")
    f = open("DB/wps.csv","w")
```
- Создание директории если нужно
- Открытие файла для записи

### Функция AddWPSLog

```python
def AddWPSLog(BSSID,SDATA):
    global WPSList
    global WPSDataList
```
- Добавление записи в лог WPS
- BSSID: MAC-адрес точки доступа
- SDATA: дополнительные данные о WPS
- Использование глобальных списков

```python
    if str(WPSList).find(BSSID)==-1:
        WPSList.append(BSSID)
        WPSDataList.append(SDATA)
```
- Проверка уникальности записи
- Добавление новой записи в списки
- Сохранение связанных данных

### Функция LoadWhiteList

```python
def LoadWhiteList():
    global WhiteList
    WhiteList = []
```
- Загрузка белого списка
- Инициализация пустого списка
- Очистка старых данных

```python
    if os.path.exists("DB/white.lst"):
        f = open("DB/white.lst","r")
        for line in f:
            if line.replace(' ','')!="":
                WhiteList.append(line.replace('\n',''))
        f.close()
```
- Чтение из файла белого списка
- Обработка каждой строки
- Удаление лишних пробелов и переносов
- Добавление в список

### Функция SaveWhiteList

```python
def SaveWhiteList():
    global WhiteList
```
- Сохранение белого списка
- Работа с глобальным списком

```python
    if not os.path.exists("DB"):
        os.makedirs("DB")
    f = open("DB/white.lst","w")
```
- Создание директории если нужно
- Открытие файла для записи

### Функция AddWhiteList

```python
def AddWhiteList(BSSID):
    global WhiteList
    if str(WhiteList).find(BSSID)==-1:
        WhiteList.append(BSSID)
```
- Добавление MAC-адреса в белый список
- Проверка на дубликаты
- Добавление только уникальных адресов

### Функция RemoveWhiteList

```python
def RemoveWhiteList(BSSID):
    global WhiteList
    if str(WhiteList).find(BSSID)!=-1:
        WhiteList.remove(BSSID)
```
- Удаление MAC-адреса из белого списка
- Проверка наличия адреса
- Удаление если адрес найден

### Функция DisplayWhiteList

```python
def DisplayWhiteList():
    DrawLine("-",fcolor.CReset,"")
    print center_text("White List")
    DrawLine("-",fcolor.CReset,"")
```
- Отображение белого списка
- Форматированный вывод заголовка
- Визуальное оформление списка

### Функция InputWhiteList

```python
def InputWhiteList():
    global BSSIDList
    global ESSIDList
```
- Ввод данных в белый список
- Использование списков BSSID и ESSID
- Интерактивный ввод данных

```python
    HeaderLine = "Add New MAC Address to White List"
    DrawLine("-",fcolor.CReset,"")
    print center_text(HeaderLine)
    DrawLine("-",fcolor.CReset,"")
```
- Форматирование интерфейса
- Вывод заголовка
- Разделительные линии

### Функция CheckMon

```python
def CheckMon():
    global IFace
    ReturnCode = 0
```
- Проверка режима мониторинга
- Использование глобального интерфейса
- Инициализация кода возврата

```python
    cmd = "iwconfig " + IFace + " | grep Mode:Monitor"
    ReturnCode = os.system(cmd)
```
- Проверка режима через iwconfig
- Поиск режима Monitor
- Возврат кода результата

### Функция EnableMonitorMode

```python
def EnableMonitorMode(IFace,IFace2,IFace3):
    printc("*","Enabling Monitor Mode for " + IFace)
```
- Включение режима мониторинга
- Параметры:
  - IFace: основной интерфейс
  - IFace2, IFace3: дополнительные интерфейсы
- Вывод информационного сообщения

```python
    cmd = "airmon-ng check kill"
    os.system(cmd)
    cmd = "airmon-ng start " + IFace
    os.system(cmd)
```
- Остановка мешающих процессов
- Запуск режима мониторинга
- Использование airmon-ng

### Функция DisableMonitorMode

```python
def DisableMonitorMode(IFace,IFace2,IFace3):
    printc("*","Disabling Monitor Mode for " + IFace)
```
- Отключение режима мониторинга
- Работа с несколькими интерфейсами
- Информирование пользователя

```python
    cmd = "airmon-ng stop " + IFace
    os.system(cmd)
    cmd = "service network-manager restart"
    os.system(cmd)
```
- Остановка мониторинга
- Перезапуск network-manager
- Восстановление нормальной работы сети

### Функция CheckDependency

```python
def CheckDependency():
    ReturnCode = 0
    DepList = ["iwconfig","aircrack-ng","reaver","pyrit"]
```
- Проверка зависимостей программы
- Список необходимых утилит
- Инициализация кода возврата

```python
    for dep in DepList:
        cmd = "which " + dep
        if os.system(cmd)!=0:
            printc("!","Dependency check failed on " + dep)
            ReturnCode = ReturnCode + 1
```
- Проверка наличия каждой утилиты
- Использование команды which
- Подсчет отсутствующих зависимостей

### Функция CheckUpdate

```python
def CheckUpdate():
    printc("*","Checking for updates...")
    cmd = "git pull origin master"
    os.system(cmd)
```
- Проверка обновлений через git
- Попытка получить изменения
- Вывод информационного сообщения

### Функция AskQuestion

```python
def AskQuestion(Question,DefaultAnswer):
    Answer = raw_input(Question)
    if Answer=="":
        Answer = DefaultAnswer
```
- Запрос ввода от пользователя
- Question: текст вопроса
- DefaultAnswer: ответ по умолчанию
- Обработка пустого ввода

### Функция DrawLine

```python
def DrawLine(LineChar,Color,BGColor):
    terminal = os.get_terminal_size()
    if BGColor=="":
        print(Color + LineChar * terminal.columns + fcolor.CReset)
    else:
        print(Color + BGColor + LineChar * terminal.columns + fcolor.CReset)
```
- Отрисовка линии в терминале
- Параметры:
  - LineChar: символ для линии
  - Color: цвет текста
  - BGColor: цвет фона
- Адаптация под размер терминала

### Функция center_text

```python
def center_text(text):
    terminal = os.get_terminal_size()
    spaces = " " * ((terminal.columns - len(text)) // 2)
    return spaces + text
```
- Центрирование текста
- Получение размера терминала
- Добавление нужного количества пробелов

### Функция printc

```python
def printc(sign,text):
    if sign=="*":
        sign = "[*] "
        signc = fcolor.CReset + "["
        signc = signc + fcolor.CGreen + "*"
        signc = signc + fcolor.CReset + "] "
```
- Форматированный вывод сообщений
- sign: тип сообщения
- Цветовое оформление
- Специальные маркеры

### Функция GetDateTime

```python
def GetDateTime():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M")
```
- Получение текущей даты и времени
- Форматирование в строку
- Использование для имен файлов

### Функция GetBSSID

```python
def GetBSSID(BSSID):
    global BSSIDList
    global ESSIDList
    global ChannelList
    global EncTypeList
```
- Получение информации о точке доступа
- BSSID: MAC-адрес точки доступа
- Использование глобальных списков
- Поиск соответствующих данных

### Функция GetChannel

```python
def GetChannel(BSSID):
    global BSSIDList
    global ChannelList
    Channel = ""
```
- Получение канала точки доступа
- BSSID: MAC-адрес точки доступа
- Поиск в списке каналов

```python
    if str(BSSIDList).find(BSSID)!=-1:
        for i in range(0,len(BSSIDList)):
            if BSSIDList[i]==BSSID:
                Channel = ChannelList[i]
```
- Поиск соответствия в списках
- Извлечение номера канала
- Обработка отсутствующих данных

### Функция GetEncType

```python
def GetEncType(BSSID):
    global BSSIDList
    global EncTypeList
    EncType = ""
```
- Получение типа шифрования
- BSSID: MAC-адрес точки доступа
- Поиск в списке типов шифрования

```python
    if str(BSSIDList).find(BSSID)!=-1:
        for i in range(0,len(BSSIDList)):
            if BSSIDList[i]==BSSID:
                EncType = EncTypeList[i]
```
- Поиск соответствия в списках
- Извлечение типа шифрования
- Возврат пустой строки если не найдено

### Функция GetESSID

```python
def GetESSID(BSSID):
    global BSSIDList
    global ESSIDList
    ESSID = ""
```
- Получение имени сети (ESSID)
- BSSID: MAC-адрес точки доступа
- Поиск в списке имен сетей

```python
    if str(BSSIDList).find(BSSID)!=-1:
        for i in range(0,len(BSSIDList)):
            if BSSIDList[i]==BSSID:
                ESSID = ESSIDList[i]
```
- Поиск соответствия в списках
- Извлечение имени сети
- Возврат пустой строки если не найдено

### Функция GetMACAddress

```python
def GetMACAddress(IFace):
    cmd = "ifconfig " + IFace + " | grep ether | awk '{print $2}'"
    MAC = subprocess.check_output(cmd,shell=True)
```
- Получение MAC-адреса интерфейса
- IFace: имя сетевого интерфейса
- Использование команд ifconfig и awk
- Возврат MAC-адреса в виде строки

### Функция GetDefaultInterface

```python
def GetDefaultInterface():
    cmd = "ip route | grep default | awk '{print $5}'"
    IFace = subprocess.check_output(cmd,shell=True)
```
- Определение интерфейса по умолчанию
- Использование команды ip route
- Извлечение имени интерфейса
- Обработка вывода команды

### Функция GetMonitorInterface

```python
def GetMonitorInterface():
    cmd = "iwconfig 2>/dev/null | grep Monitor | awk '{print $1}'"
    IFace = subprocess.check_output(cmd,shell=True)
```
- Поиск интерфейса в режиме мониторинга
- Использование iwconfig
- Фильтрация ошибок
- Извлечение имени интерфейса

### Функция GetWirelessInterface

```python
def GetWirelessInterface():
    cmd = "iwconfig 2>/dev/null | grep 802.11 | awk '{print $1}'"
    IFace = subprocess.check_output(cmd,shell=True)
```
- Поиск беспроводных интерфейсов
- Проверка поддержки 802.11
- Обработка вывода команды
- Возврат списка интерфейсов

### Функция ParseClientProbe

```python
def ParseClientProbe(line):
    global ClientMACList
    global ClientDataList
```
- Разбор данных о пробных запросах клиентов
- line: строка с данными
- Обновление глобальных списков

```python
    if line.find("Probe Request")!=-1:
        SrcMAC = line[line.find("SA:")+4:line.find("SA:")+21]
        if str(ClientMACList).find(SrcMAC)==-1:
            ClientMACList.append(SrcMAC)
```
- Поиск запросов Probe Request
- Извлечение MAC-адреса источника
- Добавление уникальных адресов

### Функция ParseClientAP

```python
def ParseClientAP(line):
    global ClientAPList
    global ClientAPDataList
```
- Разбор данных о связях клиент-AP
- line: строка с данными
- Работа со списками связей

```python
    if line.find(" - ")!=-1:
        APMAC = line[line.find("BSSID:")+7:line.find("BSSID:")+24]
        CLMAC = line[line.find("SA:")+4:line.find("SA:")+21]
```
- Извлечение MAC-адресов
- APMAC: адрес точки доступа
- CLMAC: адрес клиента

### Функция ParseEncryption

```python
def ParseEncryption(line):
    global BSSIDList
    global EncTypeList
```
- Разбор информации о шифровании
- line: строка с данными
- Обновление списков шифрования

```python
    if line.find("Authentication")!=-1:
        BSSID = line[line.find("BSSID:")+7:line.find("BSSID:")+24]
        if str(BSSIDList).find(BSSID)!=-1:
            for i in range(0,len(BSSIDList)):
                if BSSIDList[i]==BSSID:
                    if line.find("WPA (1)")!=-1:
                        EncTypeList[i] = "WPA"
```
- Определение типа аутентификации
- Обновление типа шифрования
- Поддержка различных типов WPA

### Функция ParseBeacon

```python
def ParseBeacon(line):
    global BSSIDList
    global ESSIDList
    global ChannelList
    global EncTypeList
```
- Разбор маяковых фреймов (Beacon)
- line: строка с данными
- Обновление информации о сетях

```python
    if line.find("Beacon")!=-1:
        BSSID = line[line.find("BSSID:")+7:line.find("BSSID:")+24]
        if str(BSSIDList).find(BSSID)==-1:
            BSSIDList.append(BSSID)
            ESSIDList.append("")
            ChannelList.append("")
            EncTypeList.append("")
```
- Извлечение BSSID из Beacon
- Добавление новых точек доступа
- Инициализация параметров сети

### Функция ParseESSID

```python
def ParseESSID(line):
    global BSSIDList
    global ESSIDList
```
- Разбор имени сети из пакетов
- line: строка с данными
- Обновление списка имен сетей

```python
    if line.find("ESSID:")!=-1:
        BSSID = line[line.find("BSSID:")+7:line.find("BSSID:")+24]
        ESSID = line[line.find("ESSID:")+7:line.find("\n")]
```
- Извлечение BSSID и ESSID
- Обработка специальных символов
- Сопоставление с точкой доступа

### Функция ParseChannel

```python
def ParseChannel(line):
    global BSSIDList
    global ChannelList
```
- Разбор информации о канале
- line: строка с данными
- Обновление списка каналов

```python
    if line.find("CH:")!=-1:
        BSSID = line[line.find("BSSID:")+7:line.find("BSSID:")+24]
        Channel = line[line.find("CH:")+4:line.find("(")]
```
- Извлечение номера канала
- Сопоставление с BSSID
- Обновление данных о канале

### Функция ParsePWR

```python
def ParsePWR(line):
    global BSSIDList
    global PWRList
```
- Разбор уровня сигнала
- line: строка с данными
- Обновление списка мощностей

```python
    if line.find("PWR:")!=-1:
        BSSID = line[line.find("BSSID:")+7:line.find("BSSID:")+24]
        PWR = line[line.find("PWR:")+5:line.find(" ID:")]
```
- Извлечение уровня мощности
- Сопоставление с точкой доступа
- Обработка значений мощности

### Функция ParseData

```python
def ParseData(line):
    ParseBeacon(line)
    ParsePWR(line)
    ParseChannel(line)
    ParseESSID(line)
    ParseEncryption(line)
    ParseClientProbe(line)
    ParseClientAP(line)
```
- Комплексный разбор данных
- Вызов всех парсеров
- Обработка различных типов данных

### Функция MonitorAP

```python
def MonitorAP():
    global ProcessID
    global BSSIDList
    global ESSIDList
```
- Мониторинг точек доступа
- Управление процессом мониторинга
- Сбор информации о сетях

```python
    cmd = "airodump-ng -w Dump/dump --output-format csv " + IFace
    ProcessID = subprocess.Popen(cmd,shell=True)
```
- Запуск airodump-ng
- Сохранение в CSV формате
- Управление процессом сбора

### Функция MonitorAPClient

```python
def MonitorAPClient(BSSID,Channel):
    global ProcessID
    global ClientAPList
```
- Мониторинг клиентов точки доступа
- BSSID: MAC-адрес точки доступа
- Channel: канал для мониторинга

```python
    cmd = "airodump-ng -w Dump/dump --output-format csv -d " + BSSID + " -c " + Channel + " " + IFace
    ProcessID = subprocess.Popen(cmd,shell=True)
```
- Целевой сбор данных
- Фильтрация по BSSID
- Работа на конкретном канале

### Функция MonitorStation

```python
def MonitorStation():
    global ProcessID
    global ClientMACList
```
- Мониторинг клиентских станций
- Сбор данных о клиентах
- Управление процессом

```python
    cmd = "airodump-ng -w Dump/dump --output-format csv " + IFace
    ProcessID = subprocess.Popen(cmd,shell=True)
```
- Запуск общего мониторинга
- Сохранение данных в CSV
- Анализ клиентского трафика

### Функция ReadDumpFile

```python
def ReadDumpFile():
    DumpFile = "Dump/dump-01.csv"
    while not os.path.exists(DumpFile):
        time.sleep(1)
```
- Чтение файла дампа
- Ожидание создания файла
- Обработка данных CSV

```python
    time.sleep(1)
    f = open(DumpFile,"r")
    for line in f:
        ParseData(line)
    f.close()
```
- Задержка для записи данных
- Построчный разбор файла
- Закрытие файла после чтения

### Функция RemoveDumpFile

```python
def RemoveDumpFile():
    if os.path.exists("Dump"):
        DumpList = glob.glob("Dump/*")
        for dump in DumpList:
            os.remove(dump)
```
- Удаление временных файлов дампа
- Очистка директории Dump
- Удаление всех файлов по маске

### Функция RemoveCaptureFile

```python
def RemoveCaptureFile():
    if os.path.exists("Captured"):
        CaptureList = glob.glob("Captured/*")
        for capture in CaptureList:
            os.remove(capture)
```
- Удаление захваченных файлов
- Очистка директории Captured
- Удаление всех файлов захвата

### Функция CreateFolder

```python
def CreateFolder():
    if not os.path.exists("DB"):
        os.makedirs("DB")
    if not os.path.exists("Dump"):
        os.makedirs("Dump")
    if not os.path.exists("Captured"):
        os.makedirs("Captured")
```
- Создание необходимых директорий
- DB: для базы данных
- Dump: для временных файлов
- Captured: для захваченных данных

### Функция InitializeData

```python
def InitializeData():
    global BSSIDList
    global ESSIDList
    global ChannelList
    global EncTypeList
    global ClientMACList
    global ClientDataList
```
- Инициализация глобальных списков
- Очистка старых данных
- Подготовка к новому сканированию

```python
    BSSIDList = []
    ESSIDList = []
    ChannelList = []
    EncTypeList = []
    ClientMACList = []
    ClientDataList = []
```
- Создание пустых списков
- Сброс всех данных
- Подготовка структур данных

### Функция InitializeProcessList

```python
def InitializeProcessList():
    global ProcessList
    ProcessList = []
```
- Инициализация списка процессов
- Очистка старых процессов
- Подготовка к новым операциям

### Функция SignalHandler

```python
def SignalHandler(signal, frame):
    global ProcessID
    try:
        os.kill(ProcessID.pid, signal.SIGTERM)
    except:
        pass
    RemoveDumpFile()
    sys.exit(0)
```
- Обработчик сигналов
- Корректное завершение процессов
- Очистка временных файлов
- Выход из программы

### Функция main

```python
def main():
    global IFace
    global MyMAC
    signal.signal(signal.SIGINT, SignalHandler)
```
- Основная функция программы
- Настройка обработчика сигналов
- Инициализация глобальных переменных

```python
    CheckDependency()
    CreateFolder()
    LoadWhiteList()
    LoadClientProbe()
    LoadAPClient()
    LoadWPSLog()
```
- Проверка зависимостей
- Создание структуры каталогов
- Загрузка сохраненных данных
- Подготовка к работе

### Функция DisplayMenu

```python
def DisplayMenu():
    DrawLine("=",fcolor.CReset + fcolor.BGBlue,"")
    print(center_text("WAIDPS - Wireless Auditing, Intrusion Detection & Prevention System"))
    DrawLine("=",fcolor.CReset + fcolor.BGBlue,"")
```
- Отображение главного меню
- Форматированный вывод заголовка
- Визуальное оформление

```python
    print(" 1. Start Monitoring")
    print(" 2. View Access Point")
    print(" 3. View Client")
    print(" 4. View White List")
    print(" 5. Add MAC to White List")
```
- Вывод пунктов меню
- Основные операции
- Управление белым списком

### Функция ProcessMenu

```python
def ProcessMenu(Select):
    if Select=="1":
        MonitorAP()
        while True:
            ReadDumpFile()
            DisplayAPDetail()
            time.sleep(1)
```
- Обработка выбора пользователя
- Запуск соответствующих функций
- Организация циклов мониторинга

## Общий анализ архитектуры

### Структура программы

1. **Основные компоненты**:
   - Мониторинг сетей (функции Monitor*)
   - Парсинг данных (функции Parse*)
   - Управление базой данных (функции с префиксами Save*, Load*)
   - Пользовательский интерфейс (Display*, Process*)
   - Утилиты (Check*, Get*, Initialize*)

2. **Организация данных**:
   - Использование глобальных списков для хранения информации
   - Файловая система для постоянного хранения:
     - `DB/`: База данных (crack.csv, client.csv, wps.csv, white.lst)
     - `Dump/`: Временные файлы мониторинга
     - `Captured/`: Захваченные пакеты

3. **Взаимодействие с системой**:
   - Использование системных утилит (aircrack-ng, reaver, etc.)
   - Управление сетевыми интерфейсами
   - Работа с процессами и сигналами

### Основные функциональные блоки

1. **Блок мониторинга**:
   - Сканирование точек доступа
   - Отслеживание клиентов
   - Анализ сетевого трафика
   - Сбор статистики

2. **Блок анализа**:
   - Парсинг сетевых пакетов
   - Определение типов шифрования
   - Анализ мощности сигнала
   - Обработка пробных запросов

3. **Блок хранения**:
   - Сохранение результатов
   - Управление белым списком
   - Логирование WPS попыток
   - Кэширование данных клиентов

4. **Блок интерфейса**:
   - Меню управления
   - Визуализация данных
   - Обработка пользовательского ввода
   - Форматированный вывод

## Рекомендации по улучшению

### 1. Архитектурные улучшения

1. **Модульность**:
   ```python
   # Создать отдельные модули
   monitoring/
     __init__.py
     ap_scanner.py
     client_tracker.py
   analysis/
     __init__.py
     packet_parser.py
     encryption_analyzer.py
   storage/
     __init__.py
     database.py
     file_manager.py
   ```

2. **Объектно-ориентированный подход**:
   ```python
   class AccessPoint:
       def __init__(self, bssid, essid, channel):
           self.bssid = bssid
           self.essid = essid
           self.channel = channel

   class NetworkMonitor:
       def __init__(self, interface):
           self.interface = interface
           self.access_points = []
   ```

### 2. Улучшение кода

1. **Замена глобальных переменных**:
   ```python
   class NetworkState:
       def __init__(self):
           self.bssid_list = []
           self.essid_list = []
           self.channel_list = []
   
   def monitor_ap(state: NetworkState):
       # Использование state вместо глобальных переменных
       pass
   ```

2. **Обработка ошибок**:
   ```python
   def check_dependency():
       try:
           for dep in REQUIRED_DEPENDENCIES:
               if not check_tool_exists(dep):
                   raise DependencyError(f"Missing dependency: {dep}")
       except Exception as e:
           logger.error(f"Dependency check failed: {str(e)}")
           return False
   ```

3. **Логирование**:
   ```python
   import logging

   logger = logging.getLogger(__name__)
   
   def monitor_ap():
       logger.info("Starting AP monitoring")
       try:
           # код мониторинга
           logger.debug("Processing AP data")
       except Exception as e:
           logger.error(f"Monitoring failed: {str(e)}")
   ```

### 3. Безопасность

1. **Проверка входных данных**:
   ```python
   def parse_mac_address(mac: str) -> str:
       if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
           raise ValueError("Invalid MAC address format")
       return mac.upper()
   ```

2. **Безопасная работа с файлами**:
   ```python
   def save_to_file(data, filename):
       temp_file = filename + '.tmp'
       try:
           with open(temp_file, 'w') as f:
               json.dump(data, f)
           os.replace(temp_file, filename)
       except Exception as e:
           if os.path.exists(temp_file):
               os.remove(temp_file)
           raise
   ```

### 4. Производительность

1. **Оптимизация парсинга**:
   ```python
   def parse_data(line: str) -> dict:
       # Использование регулярных выражений вместо множественных str.find()
       pattern = re.compile(r'BSSID:([\w:]+).*Channel:(\d+).*ESSID:"([^"]*)"')
       if match := pattern.search(line):
           return {
               'bssid': match.group(1),
               'channel': match.group(2),
               'essid': match.group(3)
           }
   ```

2. **Кэширование данных**:
   ```python
   from functools import lru_cache

   @lru_cache(maxsize=1000)
   def get_ap_info(bssid: str) -> dict:
       # Кэширование часто запрашиваемой информации
       return lookup_ap_details(bssid)
   ```

### 5. Тестирование

1. **Модульные тесты**:
   ```python
   def test_parse_mac_address():
       assert parse_mac_address("00:11:22:33:44:55") == "00:11:22:33:44:55"
       with pytest.raises(ValueError):
           parse_mac_address("invalid_mac")
   ```

2. **Интеграционные тесты**:
   ```python
   def test_monitor_workflow():
       monitor = NetworkMonitor("test_interface")
       monitor.start()
       assert len(monitor.access_points) > 0
       assert all(ap.bssid for ap in monitor.access_points)
   ```

Эти улучшения сделают код более:
- Поддерживаемым
- Безопасным
- Производительным
- Тестируемым
- Масштабируемым

[Конец анализа]
