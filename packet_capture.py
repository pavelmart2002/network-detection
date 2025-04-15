from scapy.all import sniff, Packet, IP, conf, Dot11, Dot11Beacon, get_if_list
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
    def __init__(self, interface="wlan2"):  # Меняем на wlan2
        try:
            if not is_admin():
                raise PermissionError("This program must be run as root!")
                
            self.is_running = False
            self.capture_thread = None
            self.packet_callback = None
            self.mac_callback = None
            self.error_callback = None
            self.interfaces = []
            self.current_interface = interface
            self.current_channel = 1
            self.channel_hop_interval = 0.5  # Добавляем интервал переключения каналов
            self.channel_lock = threading.Lock()  # Новый lock для синхронизации
            self.packet_queue = queue.Queue()  # Очередь для передачи пакетов между потоками
            logger.info(f"Initialized with interface: {self.current_interface}")
            
        except Exception as e:
            error_msg = f"Error initializing PacketCapture: {e}"
            logger.error(error_msg, exc_info=True)
            raise

    def get_interfaces(self):
        """Получение списка сетевых интерфейсов"""
        try:
            logger.info("Getting network interfaces...")
            
            # Получаем список интерфейсов через Scapy
            self.interfaces = get_network_interfaces()
            logger.info(f"Found {len(self.interfaces)} interfaces")
            
            # Выводим подробную информацию о каждом интерфейсе
            for iface in self.interfaces:
                logger.info(f"Interface details: {iface.name} - {iface.description}")
            
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
                # Можно добавить предварительную обработку, если нужно
                self.packet_queue.put(packet)
        except Exception as e:
            logger.error(f"Error queuing packet: {e}", exc_info=True)

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
                # Vendor определяем по MAC (OUI)
                vendor = self._lookup_vendor(src_mac)

                packet_info = {
                    'src': src_mac,
                    'dst': dst_mac,
                    'protocol': proto,
                    'type': pkt_type,
                    'subtype': subtype,
                    'len': length,
                    'fcs': fcs,
                    'vendor': vendor
                }
                # Вызываем callback для пакета
                if self.packet_callback:
                    self.packet_callback(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

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

    def process_queued_packets(self):
        """ВЫЗЫВАТЬ ТОЛЬКО ИЗ ГЛАВНОГО ПОТОКА! Передавать пакеты из очереди в callback GUI."""
        try:
            while not self.packet_queue.empty():
                pkt = self.packet_queue.get()
                self._process_packet(pkt)
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
                if self.current_interface not in [iface.name for iface in interfaces]:
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
                    args=(interfaces[0].name,)
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
