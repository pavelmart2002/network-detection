import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set
import time

logger = logging.getLogger(__name__)

class PacketAnalyzer:
    def __init__(self):
        # Пороговые значения
        self.THRESH_PDR = 0.9
        self.SYMBOL_TIME = 0.000016
        self.MIN_PACKETS = 5
        self.PACKET_RATE_THRESHOLD = 100
        self.SIGNAL_VARIATION_THRESHOLD = 500
        
        # Пороговые значения для атаки деаутентификации MDK3
        self.DEAUTH_THRESHOLD = 2  # Снижаем порог для мгновенного обнаружения
        self.DEAUTH_TIME_WINDOW = 0.2  # Уменьшаем окно для более быстрого реагирования
        self.DEAUTH_RATE_THRESHOLD = 3  # Настраиваем под скорость MDK3
        self.MAC_CHANGE_THRESHOLD = 1  # Мгновенное обнаружение подмены MAC
        self.BURST_THRESHOLD = 2  # Оставляем для обнаружения всплесков
        
        # Пороги для разных типов атак
        self.PROBE_REQ_THRESHOLD = 5  # Количество probe requests для срабатывания
        self.PROBE_REQ_TIME = 2.0  # Временное окно для probe requests в секундах
        
        self.PROBE_RESP_THRESHOLD = 8  # Количество probe responses для срабатывания
        self.PROBE_RESP_TIME = 5.0  # Временное окно для probe responses в секундах
        
        self.DEAUTH_THRESHOLD = 2  # Количество deauth пакетов для срабатывания
        self.DEAUTH_TIME = 1.0  # Временное окно для deauth пакетов в секундах
        
        self.FLOOD_THRESHOLD = 100  # Порог для определения флуд-атаки
        self.FLOOD_TIME_WINDOW = 5.0  # Временное окно для анализа флуд-атаки в секундах
        
        # Хранение истории пакетов для каждого источника
        self.packet_history = defaultdict(list)
        self.signal_strength_history = defaultdict(list)
        self.last_packet_time = {}
        self.window_size = 5.0  # Размер окна в секундах (float)
        
        # Счетчики для деаутентификации
        self.deauth_history = defaultdict(list)
        self.unique_targets = defaultdict(set)
        self.mac_history = defaultdict(list)
        self.burst_history = defaultdict(list)
        
        # Счетчики для статистики
        self.attack_counters = defaultdict(int)
        self.last_attack_time = {}
        
        # Счетчики для MAC-адресов и flood-атак
        self.mac_stats = {}
        self.RATE_HISTORY_WINDOW = 3.0  # Окно для хранения истории скоростей
        self.FLOOD_MIN_PACKETS = 5
        self.FLOOD_COOLDOWN = 3
        self.CLEANUP_INTERVAL = 5  # Уменьшаем интервал очистки
        self.BURST_THRESHOLD = 3
        
        # Пороги для разных типов пакетов
        self.PACKET_TYPE_THRESHOLDS = {
            'Management': 25,
            'Control': 30,
            'Data': 35
        }
        
        # Множители и пороги для разных сценариев
        self.BROADCAST_MULTIPLIER = 2.0
        self.BURST_RATIO = 2.0
        self.MIN_PACKETS_FOR_BROADCAST = 15
        self.SUSTAINED_ATTACK_THRESHOLD = 4
        
        self.JAMMING_THRESHOLD = 5
        self.last_cleanup = datetime.now()

    def _init_mac_stats(self):
        return {
            'packet_count': 0,
            'packet_times': [],
            'type_counts': {},
            'broadcast_counts': {},
            'rates': [],
            'broadcast_rates': [],
            'current_rate': 0,
            'burst_count': 0,
            'sustained_high_rate_count': 0,
            'last_rate_update': datetime.now(),
            'last_attack': None,
            'attack_status': "Normal",
            'last_seen': datetime.now(),
            'deauth_times': [],  # Добавляем отслеживание времени пакетов деаутентификации
            'deauth_burst_count': 0  # Счетчик всплесков деаутентификации
        }

    def analyze_packet(self, packet_info: Dict) -> str:
        """Анализ пакета на предмет подозрительной активности"""
        try:
            src = packet_info.get('src')
            dst = packet_info.get('dst')
            packet_type = packet_info.get('type')
            base_type = packet_info.get('base_type')
            subtype = packet_info.get('subtype')
            is_broadcast = packet_info.get('broadcast', False)
            
            if not src:
                return
                
            current_time = float(time.time())  # Преобразуем в float для уверенности
            
            # Инициализация статистики для нового MAC-адреса
            if src not in self.mac_stats:
                self.mac_stats[src] = {
                    'total': {'Management': 0, 'Control': 0, 'Data': 0},
                    'broadcast': {'Management': 0, 'Control': 0, 'Data': 0},
                    'probe_req_count': 0,
                    'probe_resp_count': 0,
                    'deauth_count': 0,
                    'auth_count': 0,
                    'last_seen': current_time,
                    'packets_window': [],  # Окно пакетов для анализа частоты
                    'suspicious_activity': set()  # Множество для хранения подозрительной активности
                }
                
            # Обновляем статистику
            stats = self.mac_stats[src]
            stats['total'][base_type] = stats['total'].get(base_type, 0) + 1
            if is_broadcast:
                stats['broadcast'][base_type] = stats['broadcast'].get(base_type, 0) + 1
                
            # Обновляем окно пакетов
            # Удаляем старые пакеты из окна
            window_cutoff = current_time - float(self.window_size)
            current_window = [p for p in stats['packets_window'] if float(p['time']) > window_cutoff]
            # Добавляем новый пакет
            current_window.append({'time': current_time, 'type': packet_type})
            stats['packets_window'] = current_window
            
            # Анализируем различные типы пакетов
            if base_type == 'Management':
                if subtype == 4:  # Probe Request
                    stats['probe_req_count'] += 1
                    # Проверяем частоту probe-запросов
                    probe_reqs = [p for p in current_window if 'Probe Request' in p['type']]
                    if len(probe_reqs) >= self.PROBE_REQ_THRESHOLD:
                        time_diff = float(probe_reqs[-1]['time']) - float(probe_reqs[0]['time'])
                        if time_diff <= self.PROBE_REQ_TIME:
                            stats['suspicious_activity'].add('High frequency of probe requests')
                            logger.warning(f"High frequency of probe requests from {src}: {len(probe_reqs)} requests in {time_diff:.2f} seconds")
                
                elif subtype == 5:  # Probe Response
                    stats['probe_resp_count'] += 1
                    # Проверяем частоту probe-ответов
                    probe_resps = [p for p in current_window if 'Probe Response' in p['type']]
                    if len(probe_resps) >= self.PROBE_RESP_THRESHOLD:
                        time_diff = float(probe_resps[-1]['time']) - float(probe_resps[0]['time'])
                        if time_diff <= self.PROBE_RESP_TIME:
                            stats['suspicious_activity'].add('High frequency of probe responses')
                            logger.warning(f"High frequency of probe responses from {src}: {len(probe_resps)} responses in {time_diff:.2f} seconds")
                
                elif subtype == 11:  # Authentication
                    stats['auth_count'] += 1
                
                elif subtype == 12:  # Deauthentication
                    stats['deauth_count'] += 1
                    # Проверяем частоту deauth-пакетов
                    deauth_packets = [p for p in current_window if 'Deauthentication' in p['type']]
                    if len(deauth_packets) >= self.DEAUTH_THRESHOLD:
                        time_diff = float(deauth_packets[-1]['time']) - float(deauth_packets[0]['time'])
                        if time_diff <= self.DEAUTH_TIME:
                            stats['suspicious_activity'].add('Possible deauthentication attack')
                            logger.warning(f"Possible deauthentication attack from {src}: {len(deauth_packets)} deauth packets in {time_diff:.2f} seconds")
            
            # Обновляем время последнего пакета
            stats['last_seen'] = current_time
            
            # Логируем информацию о пакете и статистику
            logger.debug(f"Analyzing packet: src={src}, dst={dst}, type={packet_type}, broadcast={is_broadcast}, protocol={packet_info.get('protocol')}")
            logger.debug(f"Packets in window for {src}: {len(current_window)} (total={stats['total']}, broadcast={stats['broadcast']})")
            logger.debug(f"Packet type analysis - base_type: {base_type}, subtype: {subtype}, packet_type: {packet_type}")
            
            # Если есть подозрительная активность, возвращаем информацию о ней
            if stats['suspicious_activity']:
                return {
                    'src': src,
                    'suspicious_activity': list(stats['suspicious_activity']),
                    'stats': {
                        'probe_req_count': stats['probe_req_count'],
                        'probe_resp_count': stats['probe_resp_count'],
                        'deauth_count': stats['deauth_count'],
                        'auth_count': stats['auth_count']
                    }
                }
                
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
            
        return None

    def _analyze_management_frame(self, src_mac: str, subtype: int, is_broadcast: bool) -> None:
        """Анализ фреймов управления"""
        try:
            # Проверяем тип пакета (включая специфичные для MDK3)
            is_deauth_packet = (
                subtype == 12  # деаутентификация
            )
            
            if not is_deauth_packet:
                return
                
            # Добавляем информацию в историю
            self.deauth_history[src_mac].append(datetime.now())
            
            # Очищаем старые записи
            cutoff_time = datetime.now() - timedelta(seconds=self.DEAUTH_TIME_WINDOW)
            self._clean_history(src_mac, cutoff_time)
            
            # Анализ характеристик атаки
            deauth_stats = self._analyze_deauth_patterns(src_mac)
            
            # MDK3 специфичные проверки
            is_mdk3_attack = self._check_mdk3_patterns(deauth_stats)
            
            if is_mdk3_attack:
                logger.error(
                    f"MDK3 Deauthentication attack detected!\n"
                    f"Attack characteristics:\n"
                    f"  - Deauth rate: {deauth_stats['rate']:.2f} packets/sec\n"
                    f"  - Bursts: {deauth_stats['bursts']} (intensity: {deauth_stats['burst_intensity']:.2f})\n"
                    f"  - MAC changes: {deauth_stats['mac_changes']}\n"
                    f"  - Unique targets: {deauth_stats['unique_targets']}"
                )
                
        except Exception as e:
            logger.error(f"Error analyzing management frame: {e}", exc_info=True)
            
    def _analyze_flood_attack(self, src_mac: str, base_type: str, packets_in_window: int) -> None:
        """Анализ атаки типа flood"""
        try:
            # Проверяем условия атаки
            if packets_in_window > self.FLOOD_THRESHOLD:
                logger.warning(f"Flood attack detected from {src_mac}: packets_in_window={packets_in_window}")
                
        except Exception as e:
            logger.error(f"Error analyzing flood attack: {e}", exc_info=True)
            
    def _clean_history(self, src_mac: str, cutoff_time: datetime) -> None:
        """Очистка устаревших записей"""
        self.deauth_history[src_mac] = [t for t in self.deauth_history[src_mac] if t > cutoff_time]
        
    def _analyze_deauth_patterns(self, src_mac: str) -> Dict:
        """Анализ паттернов деаутентификации"""
        try:
            deauth_times = self.deauth_history[src_mac]
            if not deauth_times:
                return {
                    'count': 0,
                    'rate': 0,
                    'bursts': 0,
                    'mac_changes': 0,
                    'unique_targets': 0,
                    'burst_intensity': 0
                }
            
            # Базовые метрики
            deauth_count = len(deauth_times)
            time_span = (max(deauth_times) - min(deauth_times)).total_seconds() or 1
            deauth_rate = deauth_count / time_span
            
            # Улучшенный анализ всплесков с учетом интенсивности
            bursts, burst_intensity = self._analyze_burst_patterns(deauth_times)
            
            # Анализ изменений MAC-адресов с учетом частоты
            mac_changes = 0
            
            return {
                'count': deauth_count,
                'rate': deauth_rate,
                'bursts': bursts,
                'mac_changes': mac_changes,
                'unique_targets': 0,
                'burst_intensity': burst_intensity
            }
            
        except Exception as e:
            logger.error(f"Error analyzing deauth patterns: {e}", exc_info=True)
            return {
                'count': 0,
                'rate': 0,
                'bursts': 0,
                'mac_changes': 0,
                'unique_targets': 0,
                'burst_intensity': 0
            }
            
    def _analyze_burst_patterns(self, times: List[datetime]) -> Tuple[int, float]:
        """Улучшенный анализ всплесков с учетом их интенсивности"""
        if len(times) < 2:
            return 0, 0.0
            
        bursts = 0
        total_intensity = 0.0
        burst_threshold = 0.1  # 100ms между пакетами в всплеске
        current_burst_size = 1
        current_burst_start = times[0]
        
        for i in range(1, len(times)):
            time_diff = (times[i] - times[i-1]).total_seconds()
            
            if time_diff < burst_threshold:
                current_burst_size += 1
            else:
                if current_burst_size > 2:  # Минимум 3 пакета для всплеска
                    bursts += 1
                    burst_duration = (times[i-1] - current_burst_start).total_seconds()
                    if burst_duration > 0:
                        intensity = current_burst_size / burst_duration
                        total_intensity += intensity
                
                current_burst_size = 1
                current_burst_start = times[i]
        
        # Проверяем последний всплеск
        if current_burst_size > 2:
            bursts += 1
            burst_duration = (times[-1] - current_burst_start).total_seconds()
            if burst_duration > 0:
                intensity = current_burst_size / burst_duration
                total_intensity += intensity
        
        avg_intensity = total_intensity / bursts if bursts > 0 else 0
        return bursts, avg_intensity
    
    def _check_mdk3_patterns(self, stats: Dict) -> bool:
        """Проверка характерных для MDK3 паттернов с улучшенной логикой"""
        try:
            # Проверяем комбинацию факторов, характерных для MDK3
            is_mdk3 = (
                # Высокая скорость деаутентификации
                stats['rate'] >= self.DEAUTH_RATE_THRESHOLD and
                # Значительное количество всплесков
                stats['bursts'] >= self.BURST_THRESHOLD and
                # Высокая интенсивность всплесков
                stats['burst_intensity'] >= 10.0 and  # Минимум 10 пакетов в секунду во время всплеска
                (
                    # Либо много изменений MAC
                    stats['mac_changes'] >= self.MAC_CHANGE_THRESHOLD or
                    # Либо атака на множество целей
                    stats['unique_targets'] >= 3
                )
            )
            
            if is_mdk3:
                logger.warning(
                    f"MDK3 pattern detected with high confidence:\n"
                    f"  - Deauth rate: {stats['rate']:.2f} packets/sec\n"
                    f"  - Bursts: {stats['bursts']} (intensity: {stats['burst_intensity']:.2f})\n"
                    f"  - MAC changes: {stats['mac_changes']}\n"
                    f"  - Unique targets: {stats['unique_targets']}"
                )
            
            return is_mdk3
            
        except Exception as e:
            logger.error(f"Error checking MDK3 patterns: {e}", exc_info=True)
            return False

    def _cleanup_old_records(self, current_time: datetime) -> None:
        """Очищаем старые записи из статистики."""
        cutoff_time = current_time - timedelta(seconds=self.RATE_HISTORY_WINDOW)
        
        # Очищаем статистику для каждого MAC-адреса
        for mac in list(self.mac_stats.keys()):
            stats = self.mac_stats[mac]
            
            # Если давно не видели этот MAC, удаляем его полностью
            if (current_time - stats['last_seen']).total_seconds() > self.RATE_HISTORY_WINDOW:
                del self.mac_stats[mac]
                logger.debug(f"Removed old MAC address: {mac}")
                continue
            
            # Сбрасываем счетчики если прошло достаточно времени с последней атаки
            if (stats['last_attack'] is not None and 
                (current_time - stats['last_attack']).total_seconds() > self.FLOOD_COOLDOWN):
                stats['burst_count'] = 0
                stats['sustained_high_rate_count'] = 0
                stats['attack_status'] = "Normal"
                logger.debug(f"Reset attack counters for {mac}")
            
            # Очищаем историю скоростей старше окна
            stats['rates'] = [r for r in stats['rates'] if r > 0]  
            stats['broadcast_rates'] = [r for r in stats['broadcast_rates'] if r > 0]  
            
    def _record_attack(self, source: str, attack_type: str) -> None:
        """Записывает информацию об атаке"""
        current_time = datetime.now()
        self.attack_counters[attack_type] += 1
        self.last_attack_time[source] = current_time
        logger.warning(f"{attack_type} detected from {source}. "
                      f"Total occurrences: {self.attack_counters[attack_type]}")
        
    def _clean_old_data(self, current_time: datetime) -> None:
        """Очистка устаревших данных"""
        for source in list(self.packet_history.keys()):
            if source in self.last_packet_time:
                if current_time - self.last_packet_time[source] > self.window_size:
                    del self.packet_history[source]
                    del self.signal_strength_history[source]
                    del self.last_packet_time[source]
                    
        # Очистка данных деаутентификации
        cutoff_time = current_time - timedelta(seconds=self.DEAUTH_TIME_WINDOW)
        for source in list(self.deauth_history.keys()):
            self.deauth_history[source] = [
                t for t in self.deauth_history[source] 
                if t > cutoff_time
            ]
            # Удаляем источник, если нет актуальных записей
            if not self.deauth_history[source]:
                del self.deauth_history[source]
                del self.unique_targets[source]
                
    def _calculate_pdr(self, source: str) -> float:
        """Расчет соотношения доставки пакетов (PDR)"""
        try:
            packets = self.packet_history[source]
            if not packets:
                return 1.0
            
            # Подсчет успешно доставленных пакетов
            successful_packets = sum(1 for p in packets if p.get("fcs") == "Valid")
            return successful_packets / len(packets)
        except Exception as e:
            logger.error(f"Error calculating PDR: {e}", exc_info=True)
            return 1.0
    
    def _check_signal_strength_variation(self, source: str) -> float:
        """Проверка вариации уровня сигнала"""
        try:
            packets = self.packet_history[source]
            if not packets:
                return 0.0
            
            # В реальной системе здесь был бы анализ RSSI
            # Сейчас просто имитируем на основе длины пакетов
            signal_strengths = [float(p.get("length", 0)) for p in packets]
            if not signal_strengths:
                return 0.0
            
            avg_strength = sum(signal_strengths) / len(signal_strengths)
            max_strength = max(signal_strengths)
            return max_strength - avg_strength
            
        except Exception as e:
            logger.error(f"Error checking signal strength variation: {e}", exc_info=True)
            return 0.0
    
    def _calculate_packet_transmission_time(self, packet_length: int) -> float:
        """Расчет времени передачи пакета"""
        # Упрощенный расчет, в реальности зависит от многих факторов
        return packet_length * self.SYMBOL_TIME
    
    def _get_pulse_width(self, source: str) -> float:
        """Получение ширины импульса"""
        try:
            packets = self.packet_history[source]
            if len(packets) < 2:
                return 0.0
            
            # Расчет среднего интервала между пакетами
            times = [datetime.strptime(p.get("time", ""), "%H:%M:%S") for p in packets]
            intervals = [(times[i+1] - times[i]).total_seconds() 
                        for i in range(len(times)-1)]
            
            return sum(intervals) / len(intervals)
        except Exception as e:
            logger.error(f"Error calculating pulse width: {e}", exc_info=True)
            return 0.0
    
    def _calculate_packet_rate(self, source: str) -> float:
        """Расчет частоты пакетов в секунду"""
        try:
            packets = self.packet_history[source]
            if len(packets) < 2:
                return 0.0
            
            first_time = datetime.strptime(packets[0].get("time", ""), "%H:%M:%S")
            last_time = datetime.strptime(packets[-1].get("time", ""), "%H:%M:%S")
            time_diff = (last_time - first_time).total_seconds()
            
            if time_diff <= 0:
                return 0.0
                
            return len(packets) / time_diff
            
        except Exception as e:
            logger.error(f"Error calculating packet rate: {e}", exc_info=True)
            return 0.0
    
    def _is_constant_jamming(self, source: str) -> bool:
        """Определение постоянного джамминга"""
        try:
            intervals = self._get_packet_intervals(source)
            if not intervals:
                return False
            
            # Проверяем постоянный высокий уровень активности
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # Условия для постоянного джамминга:
            # 1. Маленькие интервалы между пакетами
            # 2. Малая вариативность интервалов
            is_jamming = (avg_interval < 0.001 and variance < 0.0000001)
            
            if is_jamming:
                logger.warning(f"Constant jamming detected: avg_interval={avg_interval:.6f}, "
                             f"variance={variance:.6f}")
            
            return is_jamming
            
        except Exception as e:
            logger.error(f"Error checking constant jamming: {e}", exc_info=True)
            return False
    
    def _is_random_jamming(self, source: str) -> bool:
        """Определение случайного джамминга"""
        try:
            intervals = self._get_packet_intervals(source)
            if len(intervals) < self.MIN_PACKETS - 1:
                return False
            
            # Расчет статистик
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            max_interval = max(intervals)
            min_interval = min(intervals)
            
            # Условия для случайного джамминга:
            # 1. Высокая вариативность интервалов
            # 2. Значительная разница между min и max интервалами
            is_jamming = (variance > avg_interval * 2 and 
                         max_interval > min_interval * 5)
            
            if is_jamming:
                logger.warning(f"Random jamming detected: variance={variance:.6f}, "
                             f"avg={avg_interval:.6f}, min={min_interval:.6f}, "
                             f"max={max_interval:.6f}")
            
            return is_jamming
            
        except Exception as e:
            logger.error(f"Error checking random jamming: {e}", exc_info=True)
            return False
    
    def _get_packet_intervals(self, source: str) -> List[float]:
        """Получение интервалов между пакетами"""
        try:
            packets = self.packet_history[source]
            if len(packets) < 2:
                return []
            
            times = [datetime.strptime(p.get("time", ""), "%H:%M:%S") 
                    for p in packets]
            return [(times[i+1] - times[i]).total_seconds() 
                    for i in range(len(times)-1)]
                    
        except Exception as e:
            logger.error(f"Error getting packet intervals: {e}", exc_info=True)
            return []
    
    def _is_deauth_attack(self, source: str, dest: str, current_time: datetime, packet_type: str) -> bool:
        """Определение атаки деаутентификации, включая MDK3"""
        try:
            # Проверяем тип пакета (включая специфичные для MDK3)
            is_deauth_packet = (
                packet_type.lower() in ['deauth', 'deauthentication', 'disassoc', 'disassociation'] or
                packet_type.lower().startswith('0x000c') or  # деаутентификация
                packet_type.lower().startswith('0x000a') or  # диссоциация
                'authentication' in packet_type.lower() or    # аутентификация (для MDK3)
                'beacon' in packet_type.lower()              # beacon фреймы (для MDK3)
            )
            
            if not is_deauth_packet:
                return False
                
            # Добавляем информацию в историю
            self.deauth_history[source].append(current_time)
            self.unique_targets[source].add(dest)
            self.mac_history[dest].append(source)  # Отслеживаем изменения MAC
            self.burst_history[source].append(current_time)
            
            # Очищаем старые записи
            cutoff_time = current_time - timedelta(seconds=self.DEAUTH_TIME_WINDOW)
            self._clean_history(source, dest, cutoff_time)
            
            # Анализ характеристик атаки
            deauth_stats = self._analyze_deauth_patterns(source, dest)
            
            # MDK3 специфичные проверки
            is_mdk3_attack = self._check_mdk3_patterns(deauth_stats)
            
            if is_mdk3_attack:
                logger.error(
                    f"MDK3 Deauthentication attack detected!\n"
                    f"Attack characteristics:\n"
                    f"  - Deauth rate: {deauth_stats['rate']:.2f} packets/sec\n"
                    f"  - Bursts: {deauth_stats['bursts']} (intensity: {deauth_stats['burst_intensity']:.2f})\n"
                    f"  - MAC changes: {deauth_stats['mac_changes']}\n"
                    f"  - Unique targets: {deauth_stats['unique_targets']}"
                )
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error checking deauthentication attack: {e}", exc_info=True)
            return False
            
    def _clean_history(self, source: str, dest: str, cutoff_time: datetime) -> None:
        """Очистка устаревших записей"""
        self.deauth_history[source] = [t for t in self.deauth_history[source] if t > cutoff_time]
        self.burst_history[source] = [t for t in self.burst_history[source] if t > cutoff_time]
        
        # Очистка MAC истории
        if dest in self.mac_history:
            recent_macs = []
            for mac in self.mac_history[dest][-50:]:  
                if mac not in recent_macs:
                    recent_macs.append(mac)
            self.mac_history[dest] = recent_macs
            
    def _analyze_deauth_patterns(self, source: str, dest: str) -> Dict:
        """Анализ паттернов деаутентификации"""
        try:
            deauth_times = self.deauth_history[source]
            if not deauth_times:
                return {
                    'count': 0,
                    'rate': 0,
                    'bursts': 0,
                    'mac_changes': 0,
                    'unique_targets': 0,
                    'burst_intensity': 0
                }
            
            # Базовые метрики
            deauth_count = len(deauth_times)
            time_span = (max(deauth_times) - min(deauth_times)).total_seconds() or 1
            deauth_rate = deauth_count / time_span
            unique_targets = len(self.unique_targets[source])
            
            # Улучшенный анализ всплесков с учетом интенсивности
            bursts, burst_intensity = self._analyze_burst_patterns(deauth_times)
            
            # Анализ изменений MAC-адресов с учетом частоты
            mac_changes = self._count_mac_changes(dest)
            
            return {
                'count': deauth_count,
                'rate': deauth_rate,
                'bursts': bursts,
                'mac_changes': mac_changes,
                'unique_targets': unique_targets,
                'burst_intensity': burst_intensity
            }
            
        except Exception as e:
            logger.error(f"Error analyzing deauth patterns: {e}", exc_info=True)
            return {
                'count': 0,
                'rate': 0,
                'bursts': 0,
                'mac_changes': 0,
                'unique_targets': 0,
                'burst_intensity': 0
            }
            
    def _analyze_burst_patterns(self, times: List[datetime]) -> Tuple[int, float]:
        """Улучшенный анализ всплесков с учетом их интенсивности"""
        if len(times) < 2:
            return 0, 0.0
            
        bursts = 0
        total_intensity = 0.0
        burst_threshold = 0.1  # 100ms между пакетами в всплеске
        current_burst_size = 1
        current_burst_start = times[0]
        
        for i in range(1, len(times)):
            time_diff = (times[i] - times[i-1]).total_seconds()
            
            if time_diff < burst_threshold:
                current_burst_size += 1
            else:
                if current_burst_size > 2:  # Минимум 3 пакета для всплеска
                    bursts += 1
                    burst_duration = (times[i-1] - current_burst_start).total_seconds()
                    if burst_duration > 0:
                        intensity = current_burst_size / burst_duration
                        total_intensity += intensity
                
                current_burst_size = 1
                current_burst_start = times[i]
        
        # Проверяем последний всплеск
        if current_burst_size > 2:
            bursts += 1
            burst_duration = (times[-1] - current_burst_start).total_seconds()
            if burst_duration > 0:
                intensity = current_burst_size / burst_duration
                total_intensity += intensity
        
        avg_intensity = total_intensity / bursts if bursts > 0 else 0
        return bursts, avg_intensity
    
    def _count_mac_changes(self, dest: str) -> int:
        """Подсчет изменений MAC-адресов"""
        if dest not in self.mac_history:
            return 0
            
        return len(set(self.mac_history[dest]))
        
    def _check_mdk3_patterns(self, stats: Dict) -> bool:
        """Проверка характерных для MDK3 паттернов с улучшенной логикой"""
        try:
            # Проверяем комбинацию факторов, характерных для MDK3
            is_mdk3 = (
                # Высокая скорость деаутентификации
                stats['rate'] >= self.DEAUTH_RATE_THRESHOLD and
                # Значительное количество всплесков
                stats['bursts'] >= self.BURST_THRESHOLD and
                # Высокая интенсивность всплесков
                stats['burst_intensity'] >= 10.0 and  # Минимум 10 пакетов в секунду во время всплеска
                (
                    # Либо много изменений MAC
                    stats['mac_changes'] >= self.MAC_CHANGE_THRESHOLD or
                    # Либо атака на множество целей
                    stats['unique_targets'] >= 3
                )
            )
            
            if is_mdk3:
                logger.warning(
                    f"MDK3 pattern detected with high confidence:\n"
                    f"  - Deauth rate: {stats['rate']:.2f} packets/sec\n"
                    f"  - Bursts: {stats['bursts']} (intensity: {stats['burst_intensity']:.2f})\n"
                    f"  - MAC changes: {stats['mac_changes']}\n"
                    f"  - Unique targets: {stats['unique_targets']}"
                )
            
            return is_mdk3
            
        except Exception as e:
            logger.error(f"Error checking MDK3 patterns: {e}", exc_info=True)
            return False
