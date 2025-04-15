# Детальный анализ атак в WAIDPS

## 1. Процесс анализа пакетов

### Основной цикл анализа
```python
def analyze_packet(self, packet_data):
    """
    Анализ каждого входящего пакета
    """
    # Извлечение основных параметров пакета
    frame_type = packet_data.get('frame_type')
    frame_subtype = packet_data.get('frame_subtype')
    src_mac = packet_data.get('MAC_SA')
    dst_mac = packet_data.get('MAC_DA')
    timestamp = time.time()

    # Анализ в зависимости от типа фрейма
    if frame_type == 'management':
        self._analyze_management_frame(frame_subtype, src_mac, dst_mac, timestamp)
    elif frame_type == 'control':
        self._analyze_control_frame(frame_subtype, src_mac, dst_mac, timestamp)
    elif frame_type == 'data':
        self._analyze_data_frame(frame_subtype, src_mac, dst_mac, timestamp)
```

### Анализ фреймов управления
```python
def _analyze_management_frame(self, subtype, src_mac, dst_mac, timestamp):
    """
    Анализ management-фреймов
    """
    if subtype == 'deauthentication':
        self._analyze_deauth(src_mac, dst_mac, timestamp)
    elif subtype == 'authentication':
        self._analyze_auth(src_mac, timestamp)
    elif subtype == 'probe_request':
        self._analyze_probe(src_mac, timestamp)
    elif subtype == 'beacon':
        self._analyze_beacon(src_mac, timestamp)
```

## 2. Детальный анализ по типам атак

### Deauthentication Attack
```python
def _analyze_deauth(self, src_mac, dst_mac, timestamp):
    """
    Анализ пакетов деаутентификации
    """
    # Обновление счетчиков
    if src_mac not in self.deauth_counters:
        self.deauth_counters[src_mac] = {
            'count': 0,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'targets': set()
        }
    
    counter = self.deauth_counters[src_mac]
    counter['count'] += 1
    counter['last_seen'] = timestamp
    counter['targets'].add(dst_mac)

    # Проверка на атаку
    time_window = timestamp - counter['first_seen']
    if time_window > 0:
        packets_per_second = counter['count'] / time_window
        unique_targets = len(counter['targets'])

        # Критерии атаки
        if (packets_per_second > self.thresholds['deauth_packets'] and 
            unique_targets > self.thresholds['deauth_targets']):
            self._register_attack(
                AttackType.DEAUTH,
                AttackSeverity.HIGH,
                src_mac,
                {
                    'packets_per_second': packets_per_second,
                    'unique_targets': unique_targets,
                    'duration': time_window
                }
            )
```

### Authentication Flood
```python
def _analyze_auth(self, src_mac, timestamp):
    """
    Анализ пакетов аутентификации
    """
    # Обновление счетчиков
    if src_mac not in self.auth_counters:
        self.auth_counters[src_mac] = {
            'count': 0,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'intervals': []
        }
    
    counter = self.auth_counters[src_mac]
    
    # Расчет интервала между пакетами
    if counter['count'] > 0:
        interval = timestamp - counter['last_seen']
        counter['intervals'].append(interval)
    
    counter['count'] += 1
    counter['last_seen'] = timestamp

    # Анализ паттерна
    if len(counter['intervals']) >= self.min_samples:
        avg_interval = sum(counter['intervals']) / len(counter['intervals'])
        if avg_interval < self.thresholds['auth_interval']:
            self._register_attack(
                AttackType.AUTH_FLOOD,
                AttackSeverity.MEDIUM,
                src_mac,
                {
                    'average_interval': avg_interval,
                    'packet_count': counter['count']
                }
            )
```

### Evil Twin Detection
```python
def _detect_evil_twin(self, essid, bssid, channel, encryption):
    """
    Обнаружение Evil Twin атак
    """
    # Поиск существующих AP с таким же ESSID
    if essid in self.ap_database:
        existing_aps = self.ap_database[essid]
        for ap in existing_aps:
            if ap['bssid'] != bssid:
                # Проверка признаков Evil Twin
                suspicious = False
                reasons = []

                # Разные каналы
                if ap['channel'] != channel:
                    suspicious = True
                    reasons.append('different_channel')

                # Разное шифрование
                if ap['encryption'] != encryption:
                    suspicious = True
                    reasons.append('different_encryption')

                # Если найдены подозрительные признаки
                if suspicious:
                    self._register_attack(
                        AttackType.EVIL_TWIN,
                        AttackSeverity.CRITICAL,
                        bssid,
                        {
                            'original_bssid': ap['bssid'],
                            'essid': essid,
                            'reasons': reasons
                        }
                    )
```

## 3. Механизмы обнаружения

### Временное окно
```python
class TimeWindow:
    def __init__(self, duration):
        self.duration = duration
        self.events = []
    
    def add_event(self, timestamp):
        # Удаление старых событий
        current_time = time.time()
        self.events = [t for t in self.events 
                      if current_time - t <= self.duration]
        
        # Добавление нового события
        self.events.append(timestamp)
    
    def get_rate(self):
        """Возвращает количество событий в секунду"""
        if not self.events:
            return 0
        
        current_time = time.time()
        window_events = [t for t in self.events 
                        if current_time - t <= self.duration]
        
        return len(window_events) / self.duration
```

### Анализ паттернов
```python
class PatternAnalyzer:
    def __init__(self):
        self.patterns = defaultdict(list)
    
    def add_sample(self, source, value):
        self.patterns[source].append(value)
        if len(self.patterns[source]) > MAX_PATTERN_LENGTH:
            self.patterns[source].pop(0)
    
    def detect_anomaly(self, source, value, threshold):
        if len(self.patterns[source]) < MIN_SAMPLES:
            return False
        
        mean = statistics.mean(self.patterns[source])
        stdev = statistics.stdev(self.patterns[source])
        
        z_score = abs(value - mean) / stdev
        return z_score > threshold
```

## 4. Регистрация атак

### Структура атаки
```python
@dataclass
class Attack:
    type: AttackType
    severity: AttackSeverity
    source: str
    timestamp: float
    details: dict
    status: AttackStatus = AttackStatus.ACTIVE
```

### Регистрация атаки
```python
def _register_attack(self, attack_type, severity, source, details):
    """
    Регистрация обнаруженной атаки
    """
    attack = Attack(
        type=attack_type,
        severity=severity,
        source=source,
        timestamp=time.time(),
        details=details
    )
    
    # Проверка на дубликаты
    if not self._is_duplicate_attack(attack):
        self.active_attacks.append(attack)
        self._log_attack(attack)
        self._notify_attack(attack)
```

## 5. Анализ статистики

### Сбор метрик
```python
class MetricsCollector:
    def __init__(self):
        self.metrics = defaultdict(Counter)
    
    def add_metric(self, category, name, value=1):
        self.metrics[category][name] += value
    
    def get_statistics(self):
        stats = {}
        for category, counters in self.metrics.items():
            stats[category] = dict(counters)
        return stats
```

### Анализ тенденций
```python
def analyze_trends(self):
    """
    Анализ тенденций атак
    """
    for attack_type in AttackType:
        attacks = [a for a in self.attack_history 
                  if a.type == attack_type]
        
        if attacks:
            # Частота атак
            attack_times = [a.timestamp for a in attacks]
            intervals = np.diff(attack_times)
            
            # Средний интервал между атаками
            avg_interval = np.mean(intervals) if len(intervals) > 0 else 0
            
            # Тренд
            if len(attacks) >= MIN_TREND_SAMPLES:
                counts = np.array([len(attacks)])
                trend = np.polyfit(range(len(counts)), counts, 1)[0]
                
                if trend > TREND_THRESHOLD:
                    self._report_increasing_trend(attack_type, trend)
```

## 6. Оптимизация и производительность

### Очистка старых данных
```python
def _cleanup_old_data(self):
    """
    Очистка устаревших данных
    """
    current_time = time.time()
    
    # Очистка счетчиков
    for counters in [self.deauth_counters, self.auth_counters, 
                    self.probe_counters, self.beacon_counters]:
        for mac in list(counters.keys()):
            if current_time - counters[mac]['last_seen'] > DATA_RETENTION:
                del counters[mac]
    
    # Очистка истории атак
    self.attack_history = [
        attack for attack in self.attack_history
        if current_time - attack.timestamp <= HISTORY_RETENTION
    ]
```

### Оптимизация памяти
```python
def _optimize_memory(self):
    """
    Оптимизация использования памяти
    """
    # Ограничение размера списков
    for mac in self.auth_counters:
        if len(self.auth_counters[mac]['intervals']) > MAX_INTERVALS:
            self.auth_counters[mac]['intervals'] = \
                self.auth_counters[mac]['intervals'][-MAX_INTERVALS:]
    
    # Очистка неактивных атак
    self.active_attacks = [
        attack for attack in self.active_attacks
        if attack.status == AttackStatus.ACTIVE
    ]
```
