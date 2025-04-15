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

    def _capture_packets(self, iface):
        """Функция захвата пакетов"""
        try:
            logger.info(f"Starting capture on interface: {iface}")
            with self.channel_lock:
                sniff(
                    iface=iface,
                    prn=self._queue_packet,
                    store=0,
                    stop_filter=lambda x: not self.is_running
                )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}", exc_info=True)
            if self.error_callback:
                self.error_callback(f"Error during packet capture: {e}")

    def _queue_packet(self, packet):
        """Кладём обработанный пакет в очередь для главного потока"""
        try:
            if packet.haslayer(Dot11):
                # Не блокируем поток, если очередь заполнена — просто сбрасываем пакет
                try:
                    self.packet_queue.put(packet, block=False)
                except queue.Full:
                    logger.warning('[DEBUG] Packet queue is full, dropping packet')
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
                
                # Определяем, с какого интерфейса пришел пакет
                interface = getattr(packet, 'sniffed_on', self.current_interface)
                
                # Сохраняем RSSI для пеленгации
                if rssi is not None and src_mac != 'Unknown':
                    if src_mac not in self.rssi_data:
                        self.rssi_data[src_mac] = {}
                    self.rssi_data[src_mac][interface] = rssi
                
                # Вычисляем направление на источник (если включена пеленгация и есть данные)
                direction = None
                if self.triangulation_enabled and src_mac in self.rssi_data:
                    direction = self._calculate_direction(src_mac)

                # МАКСИМАЛЬНО ПРОСТОЕ ОБНАРУЖЕНИЕ АТАК
                # Логируем каждый пакет для отладки
                logger.info(f"PACKET: type={pkt_type}, subtype={subtype}, src={src_mac}, dst={dst_mac}, rssi={rssi}")
                
                # По умолчанию не атака
                ddos_status = ''
                
                # Простые правила обнаружения на основе Wireshark
                # 1. Любой пакет с типом 0 и подтипом 12 (Deauthentication)
                if pkt_type == '0' and subtype == '12':
                    ddos_status = 'DDoS/Deauth (MDK3)'
                    logger.info(f"АТАКА: Deauthentication packet from {src_mac}")
                
                # 2. Любой пакет с типом 0 и подтипом 10 (Disassociation)
                if pkt_type == '0' and subtype == '10':
                    ddos_status = 'DDoS/Deauth (MDK3)'
                    logger.info(f"АТАКА: Disassociation packet from {src_mac}")
                
                # 3. Любой пакет с типом 0 и подтипом 1 (Association Response)
                if pkt_type == '0' and subtype == '1':
                    ddos_status = 'DDoS/Deauth (MDK3)'
                    logger.info(f"АТАКА: Association Response packet from {src_mac}")
                
                # 4. Любой пакет с типом 0 и подтипом 0 (Association Request)
                if pkt_type == '0' and subtype == '0':
                    ddos_status = 'DDoS/Deauth (MDK3)'
                    logger.info(f"АТАКА: Association Request packet from {src_mac}")
                
                # 5. Любой пакет с типом 0 и подтипом 11 (Authentication)
                if pkt_type == '0' and subtype == '11':
                    ddos_status = 'DDoS/Deauth (MDK3)'
                    logger.info(f"АТАКА: Authentication packet from {src_mac}")
                
                # 6. Если от одного источника приходит много пакетов
                if not hasattr(self, 'packet_counts'):
                    self.packet_counts = {}
                
                if src_mac != 'Unknown':
                    if src_mac not in self.packet_counts:
                        self.packet_counts[src_mac] = 1
                    else:
                        self.packet_counts[src_mac] += 1
                        
                        # Если от одного источника больше 10 пакетов - это подозрительно
                        if self.packet_counts[src_mac] > 10:
                            ddos_status = 'DDoS/Deauth (MDK3)'
                            logger.info(f"АТАКА: Too many packets from {src_mac}: {self.packet_counts[src_mac]}")
                
                # Сбрасываем счетчики каждые 5 секунд
                current_time = time.time()
                if not hasattr(self, 'last_reset_time'):
                    self.last_reset_time = current_time
                elif current_time - self.last_reset_time > 5.0:
                    self.packet_counts = {}
                    self.last_reset_time = current_time
                    logger.info("Сброс счетчиков пакетов")

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
                    'rssi': rssi,
                    'direction': direction
                }
                
                # Вызываем callback для пакета
                if self.packet_callback:
                    self.packet_callback(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
            
    def _calculate_direction(self, src_mac):
        """Вычисление направления на источник на основе RSSI от разных интерфейсов"""
        try:
            # Проверяем, есть ли данные от обоих интерфейсов
            if self.current_interface in self.rssi_data[src_mac] and self.secondary_interface in self.rssi_data[src_mac]:
                rssi1 = self.rssi_data[src_mac][self.current_interface]
                rssi2 = self.rssi_data[src_mac][self.secondary_interface]
                
                # Разница в RSSI между интерфейсами
                rssi_diff = rssi1 - rssi2
                
                # Простой алгоритм определения направления
                if abs(rssi_diff) < 5:
                    return "Прямо впереди"
                elif rssi_diff > 0:
                    return "Слева"
                else:
                    return "Справа"
            
            return None
        except Exception as e:
            logger.error(f"Error calculating direction: {e}", exc_info=True)
            return None
            
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

    def set_channel(self, channel):
        """Установка канала для мониторинга"""
        try:
            if self.current_interface:
                with self.channel_lock:
                    os.system(f"iwconfig {self.current_interface} channel {channel}")
                logger.debug(f"Switched to channel {channel}")
                self.current_channel = channel
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
            
            # Запускаем захват на основном интерфейсе
            result = self.start_capture(packet_callback, mac_callback, error_callback)
            
            # Запускаем захват на вторичном интерфейсе
            if result and self.secondary_interface:
                # Создаем отдельный поток для захвата на вторичном интерфейсе
                self.secondary_capture_thread = threading.Thread(
                    target=self._capture_packets,
                    args=(self.secondary_interface,)
                )
                self.secondary_capture_thread.daemon = True
                self.secondary_capture_thread.start()
                
                logger.info(f"Triangulation capture started on {self.current_interface} and {self.secondary_interface}")
                return True
            
            return result
            
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
