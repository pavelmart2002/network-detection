from scapy.all import sniff, Packet, IP, conf, Dot11, Dot11Beacon, Dot11Deauth, get_if_list
from datetime import datetime
from typing import Callable, Optional, Dict, List
import threading
import time
import os
import logging
from logging.handlers import RotatingFileHandler
from packet_analyzer import PacketAnalyzer
import sys
import queue  # Добавляем очередь для потокобезопасной передачи данных

# Настройка логирования
log_dir = os.path.expanduser("~/.local/share/network_detection/logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'packet_capture.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Логируем информацию о системе
logger.info("=" * 50)
logger.info("Starting new session")
logger.info(f"Python version: {sys.version}")
logger.info(f"Working directory: {os.getcwd()}")
logger.info(f"Script path: {__file__}")
logger.info("=" * 50)

def is_admin():
    """Проверка прав root"""
    return os.geteuid() == 0

class PacketCapture:
    """Класс для захвата и обработки сетевых пакетов"""
    
    def __init__(self, interface=None, channel=1):
        """Инициализация захвата пакетов"""
        try:
            self.current_interface = interface
            self.secondary_interface = None  # Второй интерфейс для пеленгации
            self.current_channel = channel
            self.channel_hop_interval = 0.5  # Добавляем интервал переключения каналов
            self.channel_lock = threading.Lock()  # Новый lock для синхронизации
            self.packet_queue = queue.Queue(maxsize=500)  # Ограничиваем размер очереди
            
            # Для пеленгации
            self.rssi_data = {}  # Словарь для хранения RSSI от разных интерфейсов
            self.triangulation_enabled = False  # Флаг включения пеленгации
            
            # Необходимые атрибуты для работы
            self.is_running = False
            self.capture_thread = None
            self.secondary_capture_thread = None
            self.packet_callback = None
            self.mac_callback = None
            self.error_callback = None
            self.interfaces = []
            
            # Структуры данных для улучшенного обнаружения атак
            self.packet_stats = {}  # Статистика по пакетам для каждого MAC-адреса
            self.deauth_counts = {}  # Счетчики деаутентификационных пакетов
            self.attack_threshold = 10  # Порог для определения атаки (настраиваемый)
            self.time_window = 5.0  # Временное окно для анализа (в секундах)
            self.last_cleanup_time = time.time()  # Время последней очистки статистики
            
            # Сигнатуры известных атак
            self.attack_signatures = {
                'deauth': {
                    'description': 'Deauthentication Attack',
                    'type': '0',
                    'subtypes': ['12'],
                    'min_count': 5,  # Увеличиваем с 3 до 5
                    'time_window': 2.0,  # Уменьшаем окно с 3.0 до 2.0
                    'confidence': 0.9
                },
                'disassoc': {
                    'description': 'Disassociation Attack',
                    'type': '0',
                    'subtypes': ['10'],
                    'min_count': 5,  # Увеличиваем с 3 до 5
                    'time_window': 2.0,  # Уменьшаем окно с 3.0 до 2.0
                    'confidence': 0.8
                },
                'auth_flood': {
                    'description': 'Authentication Flood',
                    'type': '0',
                    'subtypes': ['11'],
                    'min_count': 10,  # Увеличиваем с 5 до 10
                    'time_window': 2.0,  # Уменьшаем окно с 3.0 до 2.0
                    'confidence': 0.7
                },
                'assoc_flood': {
                    'description': 'Association Flood',
                    'type': '0',
                    'subtypes': ['0', '1'],
                    'min_count': 10,  # Увеличиваем с 5 до 10
                    'time_window': 2.0,  # Уменьшаем окно с 3.0 до 2.0
                    'confidence': 0.7
                },
                'beacon_flood': {
                    'description': 'Beacon Flood',
                    'type': '0',
                    'subtypes': ['8'],
                    'min_count': 100,  # Увеличиваем с 50 до 100
                    'time_window': 3.0,  # Уменьшаем окно с 5.0 до 3.0
                    'confidence': 0.6
                }
            }
            
            logger.info(f"Initialized with interface: {self.current_interface}")
            
        except Exception as e:
            error_msg = f"Error initializing packet capture: {e}"
            logger.error(error_msg, exc_info=True)
            raise

    def get_interfaces(self):
        """Получение списка сетевых интерфейсов"""
        try:
            logger.info("Getting network interfaces...")
            
            # Получаем список интерфейсов через Scapy
            self.interfaces = get_if_list()
            logger.info(f"Found {len(self.interfaces)} interfaces")
            
            # Выводим подробную информацию о каждом интерфейсе
            for iface in self.interfaces:
                logger.info(f"Interface details: {iface}")
            
            return self.interfaces
            
        except Exception as e:
            error_msg = f"Error getting interfaces: {e}"
            logger.error(error_msg, exc_info=True)
            if self.error_callback:
                self.error_callback(error_msg)
            return []

    def _switch_channel(self, channel):
        """Переключение канала для мониторинга"""
        try:
            if self.current_interface:
                with self.channel_lock:
                    os.system(f"iwconfig {self.current_interface} channel {channel}")
                logger.debug(f"Switched to channel {channel}")
                return True
        except Exception as e:
            logger.error(f"Error switching channel: {e}")
            return False

    def _channel_hopper(self):
        """Переключение каналов для сканирования"""
        channels = range(1, 14)  # Каналы WiFi от 1 до 13
        while self.is_running:
            try:
                for channel in channels:
                    if not self.is_running:
                        break
                    self.set_channel(channel)
                    time.sleep(self.channel_hop_interval)
            except Exception as e:
                error_msg = f"Error in channel hopper: {e}"
                logger.error(error_msg, exc_info=True)
                if self.error_callback:
                    self.error_callback(error_msg)
                time.sleep(1)  # Пауза перед следующей попыткой

    def _capture_packets(self, interface):
        """Захват пакетов с указанного интерфейса"""
        try:
            logger.info(f"Starting packet capture on interface {interface}")
            
            # Используем Scapy для захвата пакетов
            sniff(
                iface=interface,
                prn=self._queue_packet,
                store=0,
                stop_filter=lambda x: not self.is_running
            )
            
            logger.info(f"Packet capture stopped on interface {interface}")
        except Exception as e:
            error_msg = f"Error in packet capture thread on {interface}: {e}"
            logger.error(error_msg, exc_info=True)
            if self.error_callback:
                self.error_callback(error_msg)
    
    def _queue_packet(self, packet):
        """Добавляет пакет в очередь для обработки в главном потоке"""
        try:
            # Добавляем информацию о том, на каком интерфейсе был пойман пакет
            if not hasattr(packet, 'sniffed_on'):
                # Пытаемся определить интерфейс из контекста
                interface = None
                for thread in threading.enumerate():
                    if thread.name.startswith('_capture_packets'):
                        if thread.args and thread.args[0]:
                            interface = thread.args[0]
                            break
                
                if interface:
                    packet.sniffed_on = interface
            
            # Добавляем пакет в очередь
            if not self.packet_queue.full():
                self.packet_queue.put(packet)
            else:
                logger.warning("Packet queue is full, dropping packet")
        except Exception as e:
            logger.error(f"Error queuing packet: {e}", exc_info=True)

    def _lookup_vendor(self, mac):
        """Грубый поиск производителя по первым трём октетам MAC (OUI)"""
        try:
            if not mac or mac == 'Unknown':
                return 'Unknown'
            oui = mac.upper().replace('-', ':').split(':')[0:3]
            oui_str = ':'.join(oui)
            # Можно подгрузить базу OUI, но для простоты — несколько примеров
            known_ouis = {
                '00:11:22': 'Cisco',
                '3A:64:43': 'Apple',
                '9E:AE:D3': 'Samsung',
                'F6:30:F7': 'Intel',
            }
            return known_ouis.get(oui_str, 'Unknown')
        except Exception:
            return 'Unknown'

    DEAUTH_SUBTYPES = ['10', '11', '12', '0', '1', '2']  # Расширенный список подтипов
    BROADCAST_MAC = ['ff:ff:ff:ff:ff:ff', 'FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00']

    def _process_packet(self, packet: Packet):
        """Обработка захваченного пакета и формирование словаря для GUI"""
        try:
            if packet.haslayer(Dot11):
                src_mac = packet.addr2 if hasattr(packet, 'addr2') and packet.addr2 else 'Unknown'
                dst_mac = packet.addr1 if hasattr(packet, 'addr1') and packet.addr1 else 'Unknown'
                proto = '802.11'
                pkt_type = str(packet.type) if hasattr(packet, 'type') else 'Unknown'
                subtype = str(packet.subtype) if hasattr(packet, 'subtype') else 'Unknown'
                length = len(packet)
                fcs = str(getattr(packet, 'fcs', '')) if hasattr(packet, 'fcs') else 'Unknown'
                vendor = self._lookup_vendor(src_mac)
                
                # Получаем RSSI (мощность сигнала) для пеленгации
                rssi = None
                if hasattr(packet, 'dBm_AntSignal'):
                    rssi = packet.dBm_AntSignal
                elif hasattr(packet, 'signal_dbm'):
                    rssi = packet.signal_dbm
                
                # Пробуем получить RSSI из разных полей (разные драйверы могут использовать разные поля)
                if rssi is None:
                    # Перебираем все возможные поля с RSSI
                    possible_rssi_fields = ['dBm_AntSignal', 'signal_dbm', 'signal', 'rssi', 'nic_signal']
                    for field in possible_rssi_fields:
                        if hasattr(packet, field):
                            rssi_value = getattr(packet, field)
                            if isinstance(rssi_value, (int, float)):
                                rssi = rssi_value
                                logger.info(f"RSSI получен из поля {field}: {rssi}")
                                break
                
                # Определяем, с какого интерфейса пришел пакет
                interface = getattr(packet, 'sniffed_on', self.current_interface)
                
                # Получаем время прибытия пакета для метода TDoA
                arrival_time = time.time()
                
                # Логируем информацию о пакете для отладки
                logger.info(f"ПАКЕТ: интерфейс={interface}, src={src_mac}, rssi={rssi}, время={arrival_time}")
                
                # Сохраняем RSSI и время прибытия для пеленгации
                if src_mac != 'Unknown':
                    if src_mac not in self.rssi_data:
                        self.rssi_data[src_mac] = {}
                    
                    # Сохраняем данные для текущего интерфейса
                    if interface not in self.rssi_data[src_mac]:
                        self.rssi_data[src_mac][interface] = {
                            'rssi': None,
                            'arrival_time': None,
                            'packet_count': 0
                        }
                    
                    # Обновляем данные
                    self.rssi_data[src_mac][interface]['rssi'] = rssi
                    self.rssi_data[src_mac][interface]['arrival_time'] = arrival_time
                    self.rssi_data[src_mac][interface]['packet_count'] += 1
                    
                    logger.info(f"Сохранены данные для {src_mac} на интерфейсе {interface}: RSSI={rssi}, время={arrival_time}")
                
                # Вычисляем направление на источник (включаем пеленгацию для всех пакетов)
                direction = None
                if self.triangulation_enabled and src_mac in self.rssi_data:
                    # Используем комбинированный метод (RSSI + TDoA)
                    direction = self._calculate_direction_combined(src_mac)
                    logger.info(f"Вычислено направление для {src_mac}: {direction}")

                # Улучшенное обнаружение атак
                ddos_status = ''
                confidence = 0.0
                
                # Игнорируем служебные пакеты и пакеты от известных производителей сетевого оборудования
                # (для уменьшения ложных срабатываний)
                ignore_detection = False
                
                # Список известных производителей сетевого оборудования (их пакеты обычно не являются атаками)
                trusted_vendors = ['Cisco', 'Aruba', 'Ubiquiti', 'Ruckus', 'Mikrotik', 'TP-Link', 'D-Link', 'Netgear']
                
                # Игнорируем пакеты от доверенных производителей
                if vendor in trusted_vendors:
                    ignore_detection = True
                    
                # Игнорируем Beacon-фреймы (тип 0, подтип 8) - они не являются атаками
                if pkt_type == '0' and subtype == '8':
                    ignore_detection = True
                
                if not ignore_detection:
                    # 1. Обнаружение атаки на основе сигнатур
                    signature_attack, signature_confidence = self._detect_attack_by_signature(src_mac, pkt_type, subtype)
                    
                    # 2. Обнаружение атаки на основе статистического анализа
                    statistical_attack, statistical_confidence = self._detect_attack_by_statistics(src_mac, pkt_type, subtype, dst_mac)
                    
                    # Выбираем результат с наибольшей уверенностью
                    if signature_attack and (not statistical_attack or signature_confidence >= statistical_confidence):
                        ddos_status = signature_attack
                        confidence = signature_confidence
                    elif statistical_attack:
                        ddos_status = statistical_attack
                        confidence = statistical_confidence
                    
                    # Дополнительная фильтрация: отбрасываем результаты с низкой уверенностью
                    if confidence < 0.6:
                        ddos_status = ''
                        confidence = 0.0
                
                # Очистка устаревшей статистики
                self._cleanup_statistics()
                
                # Формируем информацию о пакете для GUI
                packet_info = {
                    'src': src_mac,
                    'dst': dst_mac,
                    'protocol': proto,
                    'type': pkt_type,
                    'subtype': subtype,
                    'len': length,
                    'fcs': fcs,
                    'vendor': vendor,
                    'ddos_status': ddos_status,
                    'confidence': confidence if confidence > 0 else None,
                    'rssi': rssi,
                    'direction': direction
                }
                
                # Вызываем callback для пакета
                if self.packet_callback:
                    self.packet_callback(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
            
    def _detect_attack_by_signature(self, src_mac, pkt_type, subtype):
        """Обнаружение атаки на основе сигнатур"""
        current_time = time.time()
        attack_detected = None
        confidence = 0.0
        
        # Игнорируем широковещательные и специальные MAC-адреса
        if src_mac in self.BROADCAST_MAC or src_mac == 'Unknown':
            return None, 0.0
        
        # Проверяем каждую сигнатуру
        for attack_name, signature in self.attack_signatures.items():
            if pkt_type == signature['type'] and subtype in signature['subtypes']:
                # Инициализируем счетчики для этого MAC-адреса, если их еще нет
                if src_mac not in self.packet_stats:
                    self.packet_stats[src_mac] = {}
                
                if attack_name not in self.packet_stats[src_mac]:
                    self.packet_stats[src_mac][attack_name] = {
                        'count': 0,
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'packets': [],
                        'unique_destinations': set()  # Добавляем отслеживание уникальных получателей
                    }
                
                # Обновляем статистику
                stats = self.packet_stats[src_mac][attack_name]
                stats['count'] += 1
                stats['last_seen'] = current_time
                
                # Сохраняем информацию о пакете (не более 20 пакетов для экономии памяти)
                if len(stats['packets']) < 20:
                    packet_info = {
                        'type': pkt_type,
                        'subtype': subtype,
                        'time': current_time
                    }
                    stats['packets'].append(packet_info)
                
                # Проверяем, превышен ли порог для этой сигнатуры
                time_diff = current_time - stats['first_seen']
                
                # Минимальное время наблюдения перед принятием решения (для уменьшения ложных срабатываний)
                if time_diff < 1.0:
                    continue
                
                if (time_diff <= signature['time_window'] and 
                    stats['count'] >= signature['min_count']):
                    
                    # Вычисляем частоту пакетов для этой сигнатуры
                    packet_rate = stats['count'] / time_diff
                    
                    # Дополнительная проверка для сигнатур deauth и disassoc
                    if attack_name in ['deauth', 'disassoc']:
                        # Для деаутентификации и диссоциации важна высокая частота
                        if packet_rate < 2.0:  # Менее 2 пакетов в секунду - не атака
                            continue
                    
                    # Для beacon flood нужно много разных BSSID
                    if attack_name == 'beacon_flood' and len(stats['unique_destinations']) < 10:
                        continue
                    
                    # Если обнаружено несколько атак, выбираем ту, у которой выше уверенность
                    adjusted_confidence = signature['confidence']
                    
                    # Корректируем уверенность в зависимости от частоты пакетов
                    if packet_rate > 10.0:
                        adjusted_confidence = min(adjusted_confidence + 0.1, 0.95)
                    elif packet_rate < 3.0:
                        adjusted_confidence = max(adjusted_confidence - 0.2, 0.3)
                    
                    if attack_detected is None or adjusted_confidence > confidence:
                        attack_detected = signature['description']
                        confidence = adjusted_confidence
                        
                        logger.info(f"АТАКА: {attack_detected} от {src_mac}, "
                                   f"пакетов: {stats['count']}, "
                                   f"частота: {packet_rate:.2f} пакетов/сек, "
                                   f"за {time_diff:.2f} сек, "
                                   f"уверенность: {confidence:.2f}")
        
        return attack_detected, confidence

    def _detect_attack_by_statistics(self, src_mac, pkt_type, subtype, dst_mac):
        """Обнаружение атаки на основе статистического анализа"""
        current_time = time.time()
        attack_detected = None
        confidence = 0.0
        
        # Игнорируем широковещательные и специальные MAC-адреса
        if src_mac in self.BROADCAST_MAC or src_mac == 'Unknown':
            return None, 0.0
            
        # Игнорируем служебные пакеты управления (beacon, probe, etc.)
        if pkt_type == '0' and subtype == '8':  # Beacon frames
            return None, 0.0
            
        # Инициализируем статистику для этого MAC-адреса, если её еще нет
        if src_mac not in self.packet_stats:
            self.packet_stats[src_mac] = {
                'total_packets': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'packet_rate': 0.0,
                'packet_types': {},
                'destinations': {},
                'min_time_between_packets': float('inf'),
                'last_packet_time': current_time
            }
        
        # Обновляем общую статистику
        stats = self.packet_stats[src_mac]
        
        # Вычисляем минимальное время между пакетами (для обнаружения автоматизированных атак)
        if stats['total_packets'] > 0:
            time_between = current_time - stats.get('last_packet_time', 0)
            if time_between > 0:  # Защита от нулевого интервала
                stats['min_time_between_packets'] = min(stats['min_time_between_packets'], time_between)
        
        stats['last_packet_time'] = current_time
        stats['total_packets'] += 1
        stats['last_seen'] = current_time
        
        # Обновляем статистику по типам пакетов
        type_key = f"{pkt_type}_{subtype}"
        if type_key not in stats['packet_types']:
            stats['packet_types'][type_key] = 0
        stats['packet_types'][type_key] += 1
        
        # Обновляем статистику по получателям
        if dst_mac not in stats['destinations']:
            stats['destinations'][dst_mac] = 0
        stats['destinations'][dst_mac] += 1
        
        # Вычисляем частоту пакетов (пакетов в секунду)
        time_diff = current_time - stats['first_seen']
        if time_diff > 0:
            stats['packet_rate'] = stats['total_packets'] / time_diff
        
        # Минимальное время наблюдения перед принятием решения (для уменьшения ложных срабатываний)
        if time_diff < 2.0 or stats['total_packets'] < 15:
            return None, 0.0
            
        # Анализируем статистику для обнаружения атак
        
        # 1. Высокая частота пакетов (повышаем порог до 50 пакетов/сек)
        if stats['packet_rate'] > 50.0 and stats['total_packets'] > 30:
            # Дополнительная проверка на равномерность интервалов (признак автоматизированной атаки)
            if stats['min_time_between_packets'] < 0.02:  # Менее 20 мс между пакетами
                attack_detected = "Flood Attack (High packet rate)"
                confidence = min(0.5 + (stats['packet_rate'] - 50.0) / 100.0, 0.9)
                logger.info(f"АТАКА: Высокая частота пакетов от {src_mac}: "
                           f"{stats['packet_rate']:.2f} пакетов/сек, "
                           f"мин. интервал: {stats['min_time_between_packets']:.4f} сек, "
                           f"уверенность: {confidence:.2f}")
        
        # 2. Много пакетов одного типа (повышаем порог до 25 пакетов)
        for type_key, count in stats['packet_types'].items():
            if count > 25 and count / stats['total_packets'] > 0.9 and stats['total_packets'] > 30:
                attack_detected = f"Flood Attack (Type {type_key})"
                confidence = min(0.6 + (count - 25) / 50.0, 0.9)
                logger.info(f"АТАКА: Много пакетов типа {type_key} от {src_mac}: "
                           f"{count} пакетов, "
                           f"уверенность: {confidence:.2f}")
                break
        
        # 3. Много пакетов на широковещательный адрес (повышаем порог до 15 пакетов)
        for dest, count in stats['destinations'].items():
            if dest in self.BROADCAST_MAC and count > 15 and stats['total_packets'] > 20:
                attack_detected = "Broadcast Flood Attack"
                confidence = min(0.7 + (count - 15) / 20.0, 0.9)
                logger.info(f"АТАКА: Широковещательная атака от {src_mac}: "
                           f"{count} пакетов, "
                           f"уверенность: {confidence:.2f}")
                break
        
        return attack_detected, confidence

    def _cleanup_statistics(self):
        """Очистка устаревшей статистики"""
        current_time = time.time()
        
        # Очищаем статистику не чаще, чем раз в 10 секунд
        if current_time - self.last_cleanup_time < 10.0:
            return
        
        self.last_cleanup_time = current_time
        
        # Удаляем устаревшие записи
        to_delete = []
        for mac, stats in self.packet_stats.items():
            if current_time - stats.get('last_seen', 0) > self.time_window * 2:
                to_delete.append(mac)
        
        for mac in to_delete:
            del self.packet_stats[mac]
            
        logger.info(f"Очищена статистика для {len(to_delete)} MAC-адресов")
    
    def _calculate_direction_rssi(self, src_mac):
        """Вычисление направления на основе разницы RSSI (амплитудный метод)"""
        try:
            # Проверяем, есть ли данные от обоих интерфейсов
            if (self.current_interface in self.rssi_data[src_mac] and 
                self.secondary_interface in self.rssi_data[src_mac] and
                self.rssi_data[src_mac][self.current_interface]['rssi'] is not None and
                self.rssi_data[src_mac][self.secondary_interface]['rssi'] is not None):
                
                rssi1 = self.rssi_data[src_mac][self.current_interface]['rssi']
                rssi2 = self.rssi_data[src_mac][self.secondary_interface]['rssi']
                
                # Разница в RSSI между интерфейсами
                rssi_diff = rssi1 - rssi2
                
                # Логируем данные для отладки
                logger.info(f"ПЕЛЕНГАЦИЯ RSSI: MAC={src_mac}, RSSI1={rssi1}, RSSI2={rssi2}, разница={rssi_diff}")
                
                # Простой алгоритм определения направления
                if abs(rssi_diff) < 5:
                    return "Прямо впереди", 0.7  # Уверенность 70%
                elif rssi_diff > 0:
                    return "Слева", 0.6 + min(0.3, abs(rssi_diff) / 30)  # Уверенность 60-90%
                else:
                    return "Справа", 0.6 + min(0.3, abs(rssi_diff) / 30)  # Уверенность 60-90%
            
            return None, 0
        except Exception as e:
            logger.error(f"Error calculating RSSI direction: {e}", exc_info=True)
            return None, 0
    
    def _calculate_direction_tdoa(self, src_mac):
        """Вычисление направления на основе разницы времени прибытия (TDoA)"""
        try:
            # Проверяем, есть ли данные о времени прибытия от обоих интерфейсов
            if (self.current_interface in self.rssi_data[src_mac] and 
                self.secondary_interface in self.rssi_data[src_mac] and
                self.rssi_data[src_mac][self.current_interface]['arrival_time'] is not None and
                self.rssi_data[src_mac][self.secondary_interface]['arrival_time'] is not None):
                
                time1 = self.rssi_data[src_mac][self.current_interface]['arrival_time']
                time2 = self.rssi_data[src_mac][self.secondary_interface]['arrival_time']
                
                # Разница во времени прибытия (в микросекундах)
                time_diff = (time1 - time2) * 1000000  # Переводим в микросекунды
                
                # Логируем данные для отладки
                logger.info(f"ПЕЛЕНГАЦИЯ TDoA: MAC={src_mac}, Time1={time1}, Time2={time2}, разница={time_diff} мкс")
                
                # Алгоритм определения направления на основе TDoA
                # Скорость света примерно 300 000 км/с или 0.3 м/нс
                # Для расстояния между антеннами 10-20 см разница во времени будет очень маленькой
                # Поэтому используем пороговые значения
                
                # Если разница меньше порога, считаем что источник прямо впереди
                if abs(time_diff) < 50:  # 50 микросекунд
                    return "Прямо впереди", 0.8  # Уверенность 80%
                elif time_diff > 0:
                    return "Слева", 0.7 + min(0.2, abs(time_diff) / 500)  # Уверенность 70-90%
                else:
                    return "Справа", 0.7 + min(0.2, abs(time_diff) / 500)  # Уверенность 70-90%
            
            return None, 0
        except Exception as e:
            logger.error(f"Error calculating TDoA direction: {e}", exc_info=True)
            return None, 0
    
    def _calculate_direction_combined(self, src_mac):
        """Комбинированный метод пеленгации, использующий RSSI и TDoA"""
        try:
            # Получаем результаты от обоих методов
            rssi_direction, rssi_confidence = self._calculate_direction_rssi(src_mac)
            tdoa_direction, tdoa_confidence = self._calculate_direction_tdoa(src_mac)
            
            logger.info(f"КОМБИНИРОВАННАЯ ПЕЛЕНГАЦИЯ: RSSI={rssi_direction} ({rssi_confidence:.2f}), TDoA={tdoa_direction} ({tdoa_confidence:.2f})")
            
            # Если один из методов не дал результата, используем другой
            if not rssi_direction:
                return tdoa_direction
            if not tdoa_direction:
                return rssi_direction
            
            # Если результаты разные, используем метод с большей уверенностью
            if rssi_confidence > tdoa_confidence:
                logger.info(f"Выбрано направление по RSSI: {rssi_direction} (уверенность {rssi_confidence:.2f})")
                return rssi_direction
            else:
                logger.info(f"Выбрано направление по TDoA: {tdoa_direction} (уверенность {tdoa_confidence:.2f})")
                return tdoa_direction
            
        except Exception as e:
            logger.error(f"Error in combined direction calculation: {e}", exc_info=True)
            
            # В случае ошибки возвращаем результат любого метода, который сработал
            if rssi_direction:
                return rssi_direction
            if tdoa_direction:
                return tdoa_direction
            
            return None
    
    def _calculate_direction(self, src_mac):
        """Устаревший метод, оставлен для совместимости"""
        return self._calculate_direction_combined(src_mac)
    
    def set_secondary_interface(self, interface):
        """Установка вторичного интерфейса для пеленгации"""
        try:
            self.secondary_interface = interface
            logger.info(f"Secondary interface set to: {interface}")
            return True
        except Exception as e:
            logger.error(f"Error setting secondary interface: {e}", exc_info=True)
            return False
    
    def enable_triangulation(self, enabled=True):
        """Включение/выключение пеленгации"""
        self.triangulation_enabled = enabled
        logger.info(f"Triangulation {'enabled' if enabled else 'disabled'}")
        return True

    def process_queued_packets(self):
        """ВЫЗЫВАТЬ ТОЛЬКО ИЗ ГЛАВНОГО ПОТОКА! Передавать пакеты из очереди в callback GUI."""
        try:
            # Ограничиваем количество обрабатываемых пакетов за один вызов
            max_packets = 30
            processed = 0
            
            while not self.packet_queue.empty() and processed < max_packets:
                try:
                    pkt = self.packet_queue.get(block=False)
                    self._process_packet(pkt)
                    processed += 1
                except queue.Empty:
                    break
                except Exception as e:
                    logger.error(f"Error processing packet from queue: {e}", exc_info=True)
            
            if processed > 0:
                logger.debug(f"[DEBUG] Processed {processed} packets from queue")
            
        except Exception as e:
            logger.error(f"Error processing queued packets: {e}", exc_info=True)

    def start_capture(self, packet_callback: Callable, mac_callback: Optional[Callable] = None, error_callback: Optional[Callable] = None):
        """Запуск захвата пакетов в отдельном потоке"""
        try:
            if self.is_running:
                logger.warning("Capture is already running")
                return False
                
            self.packet_callback = packet_callback
            self.mac_callback = mac_callback
            self.error_callback = error_callback
            
            # Получаем список интерфейсов
            interfaces = self.get_interfaces()
            if not interfaces:
                error_msg = "No wireless interfaces found"
                logger.error(error_msg)
                if error_callback:
                    error_callback(error_msg)
                return False
            
            # Проверяем, указан ли интерфейс
            if self.current_interface:
                # Проверяем, существует ли интерфейс
                if self.current_interface not in [iface for iface in interfaces]:
                    error_msg = f"Interface {self.current_interface} not found"
                    logger.error(error_msg)
                    if error_callback:
                        error_callback(error_msg)
                    return False
                
                # Запускаем захват на указанном интерфейсе
                self.is_running = True
                self.capture_thread = threading.Thread(
                    target=self._capture_packets,
                    args=(self.current_interface,)
                )
                self.capture_thread.daemon = True
                self.capture_thread.start()
                
                # Запускаем поток переключения каналов
                self.channel_hopper_thread = threading.Thread(
                    target=self._channel_hopper
                )
                self.channel_hopper_thread.daemon = True
                self.channel_hopper_thread.start()
                
                logger.info("Capture started successfully")
                return True
            
            else:
                # Запускаем захват на первом доступном интерфейсе
                self.is_running = True
                self.capture_thread = threading.Thread(
                    target=self._capture_packets,
                    args=(interfaces[0],)
                )
                self.capture_thread.daemon = True
                self.capture_thread.start()
                
                # Запускаем поток переключения каналов
                self.channel_hopper_thread = threading.Thread(
                    target=self._channel_hopper
                )
                self.channel_hopper_thread.daemon = True
                self.channel_hopper_thread.start()
                
                logger.info("Capture started successfully")
                return True
            
        except Exception as e:
            error_msg = f"Error starting capture: {e}"
            logger.error(error_msg, exc_info=True)
            if error_callback:
                self.error_callback(error_msg)
            return False

    def stop_capture(self):
        """Остановка захвата пакетов"""
        try:
            if not self.is_running:
                logger.warning("Capture is not running")
                return
                
            logger.info("Stopping capture...")
            self.is_running = False
            
            if self.capture_thread:
                self.capture_thread.join(timeout=2)
                if self.capture_thread.is_alive():
                    logger.warning("Capture thread did not stop gracefully")
                    
            if self.channel_hopper_thread:
                self.channel_hopper_thread.join(timeout=2)
                if self.channel_hopper_thread.is_alive():
                    logger.warning("Channel hopper thread did not stop gracefully")
                    
            logger.info("Capture stopped")
            
        except Exception as e:
            error_msg = f"Error stopping capture: {e}"
            logger.error(error_msg, exc_info=True)
            if self.error_callback:
                self.error_callback(error_msg)

    def set_channel(self, channel, interface=None):
        """Установка канала для мониторинга"""
        try:
            if interface is None:
                interface = self.current_interface
            if interface:
                with self.channel_lock:
                    os.system(f"iwconfig {interface} channel {channel}")
                logger.debug(f"Switched to channel {channel} on interface {interface}")
                return True
        except Exception as e:
            logger.error(f"Error switching channel: {e}")
            return False

    def start_capture_with_triangulation(self, packet_callback: Callable, secondary_interface: str, 
                                        mac_callback: Optional[Callable] = None, 
                                        error_callback: Optional[Callable] = None):
        """Запуск захвата пакетов с пеленгацией на двух интерфейсах"""
        try:
            # Устанавливаем вторичный интерфейс
            self.set_secondary_interface(secondary_interface)
            
            # Включаем пеленгацию
            self.enable_triangulation(True)
            
            # Сохраняем callback'и
            self.packet_callback = packet_callback
            self.mac_callback = mac_callback
            self.error_callback = error_callback
            
            # Проверяем, что интерфейсы существуют
            interfaces = self.get_interfaces()
            if self.current_interface not in interfaces:
                error_msg = f"Основной интерфейс {self.current_interface} не найден"
                logger.error(error_msg)
                if error_callback:
                    error_callback(error_msg)
                return False
                
            if self.secondary_interface not in interfaces:
                error_msg = f"Вторичный интерфейс {self.secondary_interface} не найден"
                logger.error(error_msg)
                if error_callback:
                    error_callback(error_msg)
                return False
            
            # Устанавливаем канал для обоих интерфейсов
            logger.info(f"Установка канала {self.current_channel} для обоих интерфейсов")
            self.set_channel(self.current_channel, self.current_interface)
            self.set_channel(self.current_channel, self.secondary_interface)
            
            # Запускаем захват на основном интерфейсе
            logger.info(f"Запуск захвата на основном интерфейсе {self.current_interface}")
            self.is_running = True
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(self.current_interface,)
            )
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Запускаем захват на вторичном интерфейсе
            logger.info(f"Запуск захвата на вторичном интерфейсе {self.secondary_interface}")
            self.secondary_capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(self.secondary_interface,)
            )
            self.secondary_capture_thread.daemon = True
            self.secondary_capture_thread.start()
            
            logger.info(f"Triangulation capture started on {self.current_interface} and {self.secondary_interface}")
            return True
            
        except Exception as e:
            error_msg = f"Error starting triangulation capture: {e}"
            logger.error(error_msg, exc_info=True)
            if error_callback:
                error_callback(error_msg)
            return False
            
class NetworkInterface:
    """Класс для хранения информации об интерфейсе"""
    def __init__(self, name, description, guid):
        self.name = name
        self.description = description
        self.guid = guid

def get_network_interfaces():
    """Получение списка сетевых интерфейсов в Linux"""
    interfaces = []
    for iface in get_if_list():
        try:
            # Проверяем, является ли интерфейс беспроводным
            if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                with open(f"/sys/class/net/{iface}/address") as f:
                    mac = f.read().strip()
                interfaces.append(NetworkInterface(
                    name=iface,
                    description=f"Wireless Interface {iface}",
                    guid=mac
                ))
        except Exception as e:
            logger.error(f"Error getting interface {iface} info: {e}")
    return interfaces

if __name__ == "__main__":
    try:
        capture = PacketCapture()
        # Тестовый callback для пакетов
        def packet_callback(packet_info):
            print(f"Received packet: {packet_info}")
        
        capture.start_capture(packet_callback)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            capture.stop_capture()
            
    except Exception as e:
        logger.error(f"Main error: {e}", exc_info=True)
