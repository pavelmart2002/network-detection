import sys
import signal
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSplitter, QLineEdit, QLabel, QComboBox,
                             QDialog, QGridLayout, QMessageBox, QGroupBox)
from PySide6.QtCore import Qt, QTimer, QMetaObject, Slot, Q_ARG, QThread
from PySide6.QtGui import QColor, QBrush
from datetime import datetime
from packet_capture import PacketCapture
from packet_analyzer import PacketAnalyzer
import logging
import traceback
import threading
import time
import os

# Настройка логирования
log_dir = os.path.expanduser("~/.local/share/network_detection/logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   handlers=[
                       logging.FileHandler(os.path.join(log_dir, 'network_detection.log')),
                       logging.StreamHandler()
                   ])
logger = logging.getLogger(__name__)

# Глобальный обработчик исключений
def global_exception_handler(exctype, value, tb):
    error_msg = ''.join(traceback.format_exception(exctype, value, tb))
    logger.error(f"Uncaught exception:\n{error_msg}")
    QMessageBox.critical(None, "Error", f"An error occurred:\n{str(value)}")

sys.excepthook = global_exception_handler

# Обработчик системных сигналов
def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}")
    if signum in [signal.SIGINT, signal.SIGTERM]:
        logger.info("Shutting down gracefully...")
        app = QApplication.instance()
        if app:
            app.quit()

# Регистрируем обработчики сигналов
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)  # Добавляем обработку SIGHUP для Linux

class FilterDialog(QDialog):
    def __init__(self, parent=None):
        try:
            super().__init__(parent)
            self.setWindowTitle("Фильтры")
            self.setModal(True)
            layout = QGridLayout(self)

            # Поля для фильтра
            self.field_combo = QComboBox()
            self.field_combo.addItems(["source", "destination", "protocol", "type"])
            
            self.operation_combo = QComboBox()
            self.operation_combo.addItems(["contains", "equals", "greater_than"])
            
            self.value_edit = QLineEdit()
            
            self.add_button = QPushButton("Добавить фильтр")
            self.add_button.clicked.connect(self.accept)

            layout.addWidget(QLabel("Поле:"), 0, 0)
            layout.addWidget(self.field_combo, 0, 1)
            layout.addWidget(QLabel("Операция:"), 1, 0)
            layout.addWidget(self.operation_combo, 1, 1)
            layout.addWidget(QLabel("Значение:"), 2, 0)
            layout.addWidget(self.value_edit, 2, 1)
            layout.addWidget(self.add_button, 3, 1)
            logger.info("FilterDialog initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing FilterDialog: {e}", exc_info=True)
            raise

    def get_filter(self):
        try:
            return {
                "field": self.field_combo.currentText(),
                "operation": self.operation_combo.currentText(),
                "value": self.value_edit.text()
            }
            logger.debug(f"Got filter: {self.field_combo.currentText()}, {self.operation_combo.currentText()}, {self.value_edit.text()}")
        except Exception as e:
            logger.error(f"Error getting filter: {e}", exc_info=True)
            raise

class MainWindow(QMainWindow):
    """Главное окно приложения"""
    
    # Константы для таблицы пакетов
    MAX_ROWS = 100
    MAX_UPDATE_ROWS = 20
    
    def __init__(self):
        super().__init__()
        
        # Инициализация UI
        self.setWindowTitle("Обнаружение DDoS/Deauth атак")
        self.setMinimumSize(1000, 600)
        
        # Темная тема с оранжевыми акцентами
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #2D2D30;
                color: #E0E0E0;
            }
            QPushButton {
                background-color: #FF6E00;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #FF8C00;
            }
            QPushButton:pressed {
                background-color: #E65100;
            }
            QComboBox, QLineEdit {
                background-color: #3E3E42;
                color: #E0E0E0;
                border: 1px solid #555555;
                padding: 3px;
                border-radius: 2px;
            }
            QTableWidget {
                background-color: #252526;
                color: #E0E0E0;
                gridline-color: #3E3E42;
                border: 1px solid #3E3E42;
            }
            QHeaderView::section {
                background-color: #3E3E42;
                color: #E0E0E0;
                border: 1px solid #555555;
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #FF6E00;
                color: white;
            }
            QLabel {
                color: #E0E0E0;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 3px;
                margin-top: 10px;
                font-weight: bold;
                color: #E0E0E0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
            }
        """)
        
        # Создаем центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Основной layout
        main_layout = QVBoxLayout(central_widget)
        
        # Верхняя панель с кнопками
        top_panel = QHBoxLayout()
        
        # Группа для настройки интерфейса
        interface_group = QGroupBox("Настройка интерфейса")
        interface_layout = QVBoxLayout(interface_group)
        
        # Выбор интерфейса
        interface_select_layout = QHBoxLayout()
        self.interface_label = QLabel("Интерфейс:")
        self.interface_combo = QComboBox()
        self.refresh_button = QPushButton("Обновить")
        interface_select_layout.addWidget(self.interface_label)
        interface_select_layout.addWidget(self.interface_combo)
        interface_select_layout.addWidget(self.refresh_button)
        interface_layout.addLayout(interface_select_layout)
        
        # Выбор канала
        channel_select_layout = QHBoxLayout()
        self.channel_label = QLabel("Канал:")
        self.channel_combo = QComboBox()
        for i in range(1, 15):
            self.channel_combo.addItem(str(i))
        self.set_channel_button = QPushButton("Установить канал")
        channel_select_layout.addWidget(self.channel_label)
        channel_select_layout.addWidget(self.channel_combo)
        channel_select_layout.addWidget(self.set_channel_button)
        interface_layout.addLayout(channel_select_layout)
        
        # Добавляем группу интерфейса в верхнюю панель
        top_panel.addWidget(interface_group)
        
        # Группа для управления захватом
        capture_group = QGroupBox("Управление захватом")
        capture_layout = QVBoxLayout(capture_group)
        
        # Кнопки управления захватом
        capture_buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Начать захват")
        self.stop_button = QPushButton("Остановить")
        self.stop_button.setEnabled(False)
        capture_buttons_layout.addWidget(self.start_button)
        capture_buttons_layout.addWidget(self.stop_button)
        capture_layout.addLayout(capture_buttons_layout)
        
        # Добавляем группу управления захватом в верхнюю панель
        top_panel.addWidget(capture_group)
        
        # Группа для пеленгации
        triangulation_group = QGroupBox("Пеленгация источника атаки")
        triangulation_layout = QVBoxLayout(triangulation_group)
        
        # Выбор вторичного интерфейса
        secondary_interface_layout = QHBoxLayout()
        self.secondary_interface_label = QLabel("Второй интерфейс:")
        self.secondary_interface_combo = QComboBox()
        secondary_interface_layout.addWidget(self.secondary_interface_label)
        secondary_interface_layout.addWidget(self.secondary_interface_combo)
        triangulation_layout.addLayout(secondary_interface_layout)
        
        # Кнопка включения пеленгации
        triangulation_buttons_layout = QHBoxLayout()
        self.enable_triangulation_button = QPushButton("Включить пеленгацию")
        self.enable_triangulation_button.setCheckable(True)
        triangulation_buttons_layout.addWidget(self.enable_triangulation_button)
        triangulation_layout.addLayout(triangulation_buttons_layout)
        
        # Добавляем группу пеленгации в верхнюю панель
        top_panel.addWidget(triangulation_group)
        
        # Добавляем верхнюю панель в основной layout
        main_layout.addLayout(top_panel)
        
        # Таблица пакетов
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(10)  # Добавили колонку для RSSI и направления
        self.packet_table.setHorizontalHeaderLabels(["Источник", "Назначение", "Протокол", "Тип", "Подтип", "Длина", "FCS", "Производитель", "Статус", "Направление"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        main_layout.addWidget(self.packet_table)
        
        # Статусная строка
        self.statusBar().showMessage("Готов к работе")
        
        # Инициализация захвата пакетов
        self.packet_capture = PacketCapture()
        self.packet_buffer = []
        
        # Таймер для обновления таблицы
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_packet_table)
        self.update_timer.start(500)  # Обновление каждые 500 мс
        
        # Подключение сигналов
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.set_channel_button.clicked.connect(self.set_channel)
        self.enable_triangulation_button.clicked.connect(self.toggle_triangulation)
        
        # Инициализация интерфейсов
        self.refresh_interfaces()
    
    def toggle_triangulation(self):
        """Включение/выключение пеленгации"""
        if self.enable_triangulation_button.isChecked():
            self.enable_triangulation_button.setText("Выключить пеленгацию")
            self.statusBar().showMessage("Пеленгация включена")
            
            # Если захват уже запущен, перезапускаем с пеленгацией
            if self.packet_capture.is_running:
                self.stop_capture()
                self.start_capture_with_triangulation()
        else:
            self.enable_triangulation_button.setText("Включить пеленгацию")
            self.statusBar().showMessage("Пеленгация выключена")
            
            # Если захват запущен, перезапускаем без пеленгации
            if self.packet_capture.is_running:
                self.stop_capture()
                self.start_capture()
    
    def start_capture_with_triangulation(self):
        """Запуск захвата с пеленгацией"""
        try:
            # Получаем выбранные интерфейсы
            primary_interface = self.interface_combo.currentText()
            secondary_interface = self.secondary_interface_combo.currentText()
            
            if primary_interface == secondary_interface:
                QMessageBox.warning(self, "Ошибка", "Основной и вторичный интерфейсы должны отличаться")
                self.enable_triangulation_button.setChecked(False)
                self.enable_triangulation_button.setText("Включить пеленгацию")
                return
            
            # Создаем новый экземпляр PacketCapture
            self.packet_capture = PacketCapture(primary_interface)
            
            # Запускаем захват с пеленгацией
            success = self.packet_capture.start_capture_with_triangulation(
                self.process_packet,
                secondary_interface,
                self.process_mac_address,
                self.process_error
            )
            
            if success:
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
                self.interface_combo.setEnabled(False)
                self.secondary_interface_combo.setEnabled(False)
                self.statusBar().showMessage(f"Захват запущен с пеленгацией на интерфейсах {primary_interface} и {secondary_interface}")
            else:
                self.statusBar().showMessage("Ошибка запуска захвата с пеленгацией")
                self.enable_triangulation_button.setChecked(False)
                self.enable_triangulation_button.setText("Включить пеленгацию")
        
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка запуска захвата с пеленгацией: {e}")
            self.enable_triangulation_button.setChecked(False)
            self.enable_triangulation_button.setText("Включить пеленгацию")
    
    def start_capture(self):
        """Запуск захвата пакетов"""
        try:
            # Если включена пеленгация, используем другой метод
            if self.enable_triangulation_button.isChecked():
                self.start_capture_with_triangulation()
                return
            
            # Получаем выбранный интерфейс
            interface = self.interface_combo.currentText()
            
            # Создаем новый экземпляр PacketCapture
            self.packet_capture = PacketCapture(interface)
            
            # Запускаем захват
            success = self.packet_capture.start_capture(
                self.process_packet,
                self.process_mac_address,
                self.process_error
            )
            
            if success:
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
                self.interface_combo.setEnabled(False)
                self.secondary_interface_combo.setEnabled(False)
                self.statusBar().showMessage(f"Захват запущен на интерфейсе {interface}")
            else:
                self.statusBar().showMessage("Ошибка запуска захвата")
        
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка запуска захвата: {e}")
    
    def refresh_interfaces(self):
        """Обновление списка интерфейсов"""
        try:
            # Очищаем комбобоксы
            self.interface_combo.clear()
            self.secondary_interface_combo.clear()
            
            # Получаем список интерфейсов
            interfaces = self.packet_capture.get_interfaces()
            
            # Заполняем комбобоксы
            for iface in interfaces:
                self.interface_combo.addItem(iface)
                self.secondary_interface_combo.addItem(iface)
            
            # Выбираем разные интерфейсы по умолчанию, если доступно
            if self.interface_combo.count() > 1:
                self.interface_combo.setCurrentIndex(0)
                self.secondary_interface_combo.setCurrentIndex(1)
            
            self.statusBar().showMessage(f"Найдено {len(interfaces)} интерфейсов")
        
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка обновления интерфейсов: {e}")
    
    def update_packet_table(self):
        """Обновление таблицы пакетов"""
        try:
            # Обрабатываем пакеты из очереди
            self.packet_capture.process_queued_packets()
            
            # Если нет пакетов, выходим
            if not self.packet_buffer:
                return
            
            # Ограничиваем количество отображаемых строк
            display_packets = self.packet_buffer[-self.MAX_ROWS:]
            
            # Ограничиваем количество обновляемых строк за раз
            if len(display_packets) > self.MAX_UPDATE_ROWS:
                display_packets = display_packets[-self.MAX_UPDATE_ROWS:]
            
            # Устанавливаем количество строк
            current_row_count = self.packet_table.rowCount()
            new_row_count = min(len(self.packet_buffer), self.MAX_ROWS)
            
            if new_row_count > current_row_count:
                self.packet_table.setRowCount(new_row_count)
            
            # Обновляем таблицу
            for i, packet in enumerate(display_packets):
                row = current_row_count - len(display_packets) + i
                
                if row >= 0 and row < self.MAX_ROWS:
                    # Заполняем ячейки таблицы
                    self.packet_table.setItem(row, 0, QTableWidgetItem(packet.get('src', '')))
                    self.packet_table.setItem(row, 1, QTableWidgetItem(packet.get('dst', '')))
                    self.packet_table.setItem(row, 2, QTableWidgetItem(packet.get('protocol', '')))
                    self.packet_table.setItem(row, 3, QTableWidgetItem(packet.get('type', '')))
                    self.packet_table.setItem(row, 4, QTableWidgetItem(packet.get('subtype', '')))
                    self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet.get('len', ''))))
                    self.packet_table.setItem(row, 6, QTableWidgetItem(packet.get('fcs', '')))
                    self.packet_table.setItem(row, 7, QTableWidgetItem(packet.get('vendor', '')))
                    
                    # Статус DDoS/Deauth
                    ddos_status = packet.get('ddos_status', '')
                    status_item = QTableWidgetItem(ddos_status)
                    
                    # Выделяем красным, если это атака
                    if ddos_status:
                        status_item.setBackground(QColor(255, 0, 0, 100))
                        status_item.setForeground(QColor(255, 255, 255))
                    
                    self.packet_table.setItem(row, 8, status_item)
                    
                    # Направление на источник (для пеленгации)
                    direction = packet.get('direction', '')
                    direction_item = QTableWidgetItem(direction)
                    
                    # Выделяем зеленым, если есть информация о направлении
                    if direction:
                        direction_item.setBackground(QColor(0, 255, 0, 100))
                        direction_item.setForeground(QColor(0, 0, 0))
                    
                    self.packet_table.setItem(row, 9, direction_item)
            
            # Прокручиваем к последней строке
            self.packet_table.scrollToBottom()
            
        except Exception as e:
            logger.error(f"Error updating packet table: {e}", exc_info=True)

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        logger.critical(f"Application crashed: {e}", exc_info=True)
        sys.exit(1)
