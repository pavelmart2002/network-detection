import sys
import signal
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSplitter, QLineEdit, QLabel, QComboBox,
                             QDialog, QGridLayout, QMessageBox)
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
    def __init__(self):
        """Инициализация главного окна"""
        try:
            super().__init__()
            self.setWindowTitle("Network Detection")
            self.setGeometry(100, 100, 1200, 800)
            
            # --- DARK THEME WITH ORANGE ACCENTS ---
            self.setStyleSheet('''
                QMainWindow, QWidget {
                    background-color: #181818;
                    color: #FFA500;
                }
                QTableWidget, QHeaderView::section {
                    background-color: #222;
                    color: #FFA500;
                    border: 1px solid #FFA500;
                }
                QTableWidget::item {
                    background-color: #181818;
                    color: #FFA500;
                    padding: 2px 6px;
                }
                QTableWidget::item:alternate {
                    background-color: #232323;
                }
                QTableWidget QTableCornerButton::section {
                    background-color: #181818;
                    border: 1px solid #FFA500;
                }
                QLineEdit, QComboBox, QDialog, QPushButton {
                    background-color: #222;
                    color: #FFA500;
                    border: 1px solid #FFA500;
                }
                QPushButton {
                    background-color: #181818;
                    color: #FFA500;
                    border: 2px solid #FFA500;
                    border-radius: 5px;
                    padding: 4px 12px;
                }
                QPushButton:hover {
                    background-color: #FFA500;
                    color: #181818;
                }
                QScrollBar:vertical, QScrollBar:horizontal {
                    background: #222;
                    border: 1px solid #FFA500;
                }
                QScrollBar::handle {
                    background: #FFA500;
                    border-radius: 4px;
                }
                QHeaderView::section {
                    background: #222;
                    color: #FFA500;
                    border: 1px solid #FFA500;
                }
                QMenuBar, QMenu, QMenu::item {
                    background-color: #181818;
                    color: #FFA500;
                }
                QMenu::item:selected {
                    background-color: #FFA500;
                    color: #181818;
                }
                QMessageBox {
                    background-color: #181818;
                    color: #FFA500;
                }
            ''')
            # --------------------------------------
            
            # Инициализация UI
            self.init_ui()
            
            # Инициализация данных
            self.mac_data = {}  # Словарь для хранения информации о MAC-адресах
            self.packet_buffer = []  # Список для хранения информации о пакетах
            
            # Инициализация буферов для пакетов и MAC-адресов
            self.BUFFER_SIZE = 1000
            
            # Цвета для разных состояний
            self.COLORS = {
                'normal': QColor(255, 165, 0),  # Оранжевый
                'warning': QColor(255, 255, 0),   # Желтый
                'danger': QColor(255, 0, 0),      # Красный
                'High frequency of probe requests': QColor(255, 165, 0),     # Оранжевый
                'High frequency of probe responses': QColor(255, 140, 0),    # Темно-оранжевый
                'Possible deauthentication attack': QColor(255, 0, 0),       # Красный
                'DDoS/Deauth (MDK3)': QColor(186, 85, 211),  # Фиолетовый (ярко выделяется)
            }
            
            # Создаем таймер для обновления таблиц
            self.update_timer = QTimer(self)
            self.update_timer.timeout.connect(self.update_tables)
            self.update_timer.start(1000)  # Обновление каждую секунду
            
            # Таймер для безопасной обработки пакетов из очереди (каждые 100 мс)
            self.packet_queue_timer = QTimer(self)
            self.packet_queue_timer.timeout.connect(self.process_packet_queue)
            self.packet_queue_timer.start(500)  # Было 100, теперь 500 мс для теста
            
            logger.info("MainWindow initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing MainWindow: {e}", exc_info=True)
            
    def init_ui(self):
        """Инициализация UI"""
        try:
            # Инициализация захвата пакетов
            self.packet_capture = None
            self.packet_analyzer = PacketAnalyzer()
            self.init_packet_capture()
            
            # Буфер для пакетов
            self.MAX_ROWS = 1000
            
            # Таймер для проверки состояния
            self.check_timer = QTimer()
            self.check_timer.moveToThread(self.thread())
            self.check_timer.timeout.connect(self.check_capture_status)
            
            # Таймер для автоперезапуска
            self.restart_timer = QTimer()
            self.restart_timer.moveToThread(self.thread())
            self.restart_timer.timeout.connect(self.restart_capture_if_needed)
            
            # Создаем центральный виджет и layout
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            main_layout = QVBoxLayout(central_widget)

            # Создаем верхнюю панель с кнопками и фильтром
            button_layout = QHBoxLayout()
            self.start_button = QPushButton("Старт")
            self.stop_button = QPushButton("Стоп")
            self.settings_button = QPushButton("Настройки")
            self.filter_button = QPushButton("Фильтры")
            
            button_layout.addWidget(self.start_button)
            button_layout.addWidget(self.stop_button)
            button_layout.addWidget(self.filter_button)
            button_layout.addWidget(self.settings_button)
            button_layout.addStretch()
            
            main_layout.addLayout(button_layout)

            # Создаем поле поиска
            search_layout = QHBoxLayout()
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Поиск...")
            self.search_input.textChanged.connect(self.apply_search)
            search_layout.addWidget(QLabel("Поиск:"))
            search_layout.addWidget(self.search_input)
            main_layout.addLayout(search_layout)

            # Создаем разделитель для таблиц
            splitter = QSplitter(Qt.Vertical)

            # Верхняя таблица для пакетов
            self.packets_table = QTableWidget()
            self.packets_table.setColumnCount(8)
            self.packets_table.setHorizontalHeaderLabels([
                "Time", "Destination", "Protocol", "Length",
                "Type", "Source", "FCS", "Status"
            ])
            header = self.packets_table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeToContents)
            
            # Нижняя таблица для MAC-адресов
            self.mac_table = QTableWidget()
            self.mac_table.setColumnCount(5)
            self.mac_table.setHorizontalHeaderLabels([
                "MAC Address", "Packets", "Last Seen", "Type", "Vendor"
            ])
            header = self.mac_table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeToContents)

            splitter.addWidget(self.packets_table)
            splitter.addWidget(self.mac_table)
            
            # Устанавливаем соотношение размеров таблиц
            splitter.setStretchFactor(0, 2)
            splitter.setStretchFactor(1, 1)
            
            main_layout.addWidget(splitter)

            # Подключаем обработчики событий
            self.start_button.clicked.connect(self.start_capture)
            self.stop_button.clicked.connect(self.stop_capture)
            self.settings_button.clicked.connect(self.show_settings)
            self.filter_button.clicked.connect(self.show_filter_dialog)

            # Начальное состояние кнопок
            self.stop_button.setEnabled(False)

            # --- Компактные строки таблицы и чередование цветов ---
            self.packets_table.setAlternatingRowColors(True)
            self.packets_table.verticalHeader().setDefaultSectionSize(22)
            self.packets_table.setStyleSheet("QTableWidget::item { padding: 2px 6px; }")
            self.mac_table.setAlternatingRowColors(True)
            self.mac_table.verticalHeader().setDefaultSectionSize(22)
            self.mac_table.setStyleSheet("QTableWidget::item { padding: 2px 6px; }")

            logger.info("UI initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing UI: {e}", exc_info=True)
            raise

    def init_packet_capture(self):
        """Инициализация захвата пакетов"""
        try:
            if self.packet_capture:
                self.packet_capture.stop_capture()
            self.packet_capture = PacketCapture()
            logger.info("PacketCapture initialized")
        except Exception as e:
            logger.error(f"Error initializing PacketCapture: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to initialize packet capture: {str(e)}")

    def check_capture_status(self):
        """Проверка состояния захвата пакетов"""
        try:
            if not hasattr(self, 'packet_capture') or not self.packet_capture:
                return
                
            if not self.packet_capture.is_running and self.stop_button.isEnabled():
                logger.warning("Packet capture stopped unexpectedly")
                self.stop_capture()
                QMessageBox.warning(self, "Warning", 
                    "Захват пакетов был неожиданно остановлен. Попробуйте запустить снова.")
        except Exception as e:
            logger.error(f"Error checking capture status: {e}", exc_info=True)

    def restart_capture_if_needed(self):
        """Автоматический перезапуск захвата при необходимости"""
        try:
            if not hasattr(self, 'packet_capture') or not self.packet_capture:
                return
                
            if (not self.packet_capture.is_running and 
                self.stop_button.isEnabled()):
                logger.info("Attempting to restart packet capture...")
                self.stop_capture()
                # Небольшая задержка перед перезапуском
                QTimer.singleShot(1000, self.start_capture)
        except Exception as e:
            logger.error(f"Error restarting capture: {e}", exc_info=True)

    def update_tables(self):
        """Обновление таблиц с данными"""
        try:
            current_time = time.time()
            rows_to_remove = []
            
            # Обновляем таблицу MAC-адресов
            for row in range(self.mac_table.rowCount()):
                mac = self.mac_table.item(row, 0).text()
                last_seen_str = self.mac_table.item(row, 2).text()
                try:
                    # Пробуем преобразовать как float (старый формат)
                    last_seen = float(last_seen_str)
                except ValueError:
                    # Если не получилось — пробуем как строку времени
                    from datetime import datetime
                    last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S').timestamp()
                if current_time - last_seen > 60:  # Удаляем записи старше 60 секунд
                    rows_to_remove.append(row)
                    
            # Удаляем устаревшие записи
            for row in reversed(rows_to_remove):
                self.mac_table.removeRow(row)
                
            # Обновляем цвета строк на основе статуса
            for row in range(self.mac_table.rowCount()):
                mac = self.mac_table.item(row, 0).text()
                if mac in self.mac_data:
                    status = self.mac_data[mac].get('status', 'normal')
                    if isinstance(status, dict) and 'suspicious_activity' in status:
                        # Если есть подозрительная активность, используем первую как статус
                        activities = status['suspicious_activity']
                        if activities:
                            status = activities[0]  # Берем первую активность как основную
                        else:
                            status = 'normal'
                    color = self.COLORS.get(status, self.COLORS['normal'])
                    
                    for col in range(self.mac_table.columnCount()):
                        item = self.mac_table.item(row, col)
                        if item:
                            item.setBackground(color)
            
        except Exception as e:
            logger.error(f"Error updating tables: {e}", exc_info=True)

    def add_packet_to_table(self, packet_data):
        """Добавление пакета в буфер"""
        try:
            self.packet_buffer.append(packet_data)
            if len(self.packet_buffer) > self.BUFFER_SIZE:
                self.packet_buffer.pop(0)  # Удаляем старые пакеты если буфер переполнен
        except Exception as e:
            logger.error(f"Error adding packet to buffer: {e}", exc_info=True)

    def add_mac_to_table(self, mac_address):
        """Добавление MAC-адреса в таблицу"""
        try:
            if mac_address not in self.mac_data:
                self.mac_data[mac_address] = {
                    'packets': 0,
                    'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'Unknown',
                    'vendor': 'Unknown'
                }
            
            # Обновляем информацию
            self.mac_data[mac_address]['packets'] += 1
            self.mac_data[mac_address]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Обновляем таблицу
            self.update_mac_table()
            
        except Exception as e:
            logger.error(f"Error adding MAC to table: {e}", exc_info=True)

    def update_mac_table(self):
        """Обновление таблицы MAC-адресов"""
        try:
            self.mac_table.setRowCount(len(self.mac_data))
            for row, (mac, data) in enumerate(self.mac_data.items()):
                self.mac_table.setItem(row, 0, QTableWidgetItem(mac))
                self.mac_table.setItem(row, 1, QTableWidgetItem(str(data['packets'])))
                self.mac_table.setItem(row, 2, QTableWidgetItem(data['last_seen']))
                self.mac_table.setItem(row, 3, QTableWidgetItem(data['type']))
                self.mac_table.setItem(row, 4, QTableWidgetItem(data['vendor']))
        except Exception as e:
            logger.error(f"Error updating MAC table: {e}", exc_info=True)

    def start_capture(self):
        """Начало захвата пакетов"""
        try:
            if not self.packet_capture:
                self.init_packet_capture()
            
            # Запускаем таймеры в главном потоке
            self.check_timer.start(1000)
            self.restart_timer.start(5000)
            
            self.packet_capture.start_capture(
                self.add_packet_to_buffer,
                self.add_mac_to_table,
                self.handle_capture_error
            )
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            logger.info("Packet capture started")
            
        except Exception as e:
            logger.error(f"Error starting capture: {e}", exc_info=True)
            self._show_error_dialog(f"Failed to start capture: {str(e)}")
            
    def add_packet_to_buffer(self, packet_data):
        """Добавляет пакет в буфер и обновляет таблицу"""
        try:
            # Логируем входные данные для отладки
            logger.debug(f"[DEBUG] add_packet_to_buffer received: {packet_data}")
            # Получаем статус из анализатора
            status = self.packet_analyzer.analyze_packet(packet_data)
            # Проверка на ddos_status из packet_info (от packet_capture)
            ddos_status = packet_data.get('ddos_status', '')
            if ddos_status:
                if not status:
                    status = ddos_status
                else:
                    # Если уже есть статус, добавляем ddos_status как дополнительный
                    if isinstance(status, set):
                        status.add(ddos_status)
                    elif isinstance(status, str):
                        status = {status, ddos_status}
            # Логируем итоговый статус
            logger.debug(f"[DEBUG] add_packet_to_buffer status: {status}")
            # Добавляем пакет в буфер
            packet_info = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'destination': packet_data.get('dst', 'Unknown'),
                'protocol': packet_data.get('protocol', 'Unknown'),
                'length': str(packet_data.get('len', 0)),
                'type': packet_data.get('type', 'Unknown'),
                'source': packet_data.get('src', 'Unknown'),
                'fcs': packet_data.get('fcs', 'Unknown'),
                'status': status
            }
            
            self.packet_buffer.append(packet_info)
            
            # Ограничиваем размер буфера
            if len(self.packet_buffer) > self.BUFFER_SIZE:
                logger.warning(f"[DEBUG] Packet buffer overflow: {len(self.packet_buffer)} > {self.BUFFER_SIZE}")
                self.packet_buffer.pop(0)
            
            # Обновляем таблицу
            self.update_packet_table()
            
        except Exception as e:
            logger.error(f"Error adding packet to buffer: {e}", exc_info=True)

    def update_packet_table(self):
        """Обновляет таблицу пакетов на основе данных из буфера"""
        try:
            # Получаем все новые пакеты из буфера
            current_rows = self.packets_table.rowCount()
            new_packets = self.packet_buffer[current_rows:]
            
            # Если таблица слишком большая, очищаем её
            if current_rows > self.MAX_ROWS:
                self.packets_table.setRowCount(0)
                current_rows = 0
                new_packets = self.packet_buffer[-self.MAX_ROWS:]  # Берем последние MAX_ROWS пакетов
            
            # Добавляем новые пакеты
            for packet_info in new_packets:
                row = self.packets_table.rowCount()
                self.packets_table.insertRow(row)
                
                # Заполняем ячейки
                timestamp_item = QTableWidgetItem(packet_info['time'])
                destination_item = QTableWidgetItem(packet_info['destination'])
                protocol_item = QTableWidgetItem(packet_info['protocol'])
                length_item = QTableWidgetItem(packet_info['length'])
                type_item = QTableWidgetItem(packet_info['type'])
                source_item = QTableWidgetItem(packet_info['source'])
                fcs_item = QTableWidgetItem(packet_info['fcs'])
                
                # Convert status from set to string
                status = packet_info['status']
                if isinstance(status, set):
                    status = ', '.join(status) if status else 'normal'
                elif not status:
                    status = 'normal'
                status_item = QTableWidgetItem(str(status))
                
                # Устанавливаем цвет фона и явно задаём цвет текста для тёмной темы
                if status in self.COLORS:
                    color = self.COLORS[status]
                    for item in [timestamp_item, destination_item, protocol_item, 
                               length_item, type_item, source_item, fcs_item, status_item]:
                        item.setBackground(color)
                        item.setForeground(QBrush(QColor('#FFA500')))
                else:
                    for item in [timestamp_item, destination_item, protocol_item, 
                               length_item, type_item, source_item, fcs_item, status_item]:
                        item.setForeground(QBrush(QColor('#FFA500')))
                
                # Добавляем элементы в таблицу
                self.packets_table.setItem(row, 0, timestamp_item)
                self.packets_table.setItem(row, 1, destination_item)
                self.packets_table.setItem(row, 2, protocol_item)
                self.packets_table.setItem(row, 3, length_item)
                self.packets_table.setItem(row, 4, type_item)
                self.packets_table.setItem(row, 5, source_item)
                self.packets_table.setItem(row, 6, fcs_item)
                self.packets_table.setItem(row, 7, status_item)
            
            # Прокручиваем таблицу к последней строке
            if new_packets:
                self.packets_table.scrollToBottom()
            
        except Exception as e:
            logger.error(f"Error updating packet table: {e}", exc_info=True)

    def handle_capture_error(self, error_msg: str):
        """Обработка ошибок захвата пакетов"""
        try:
            logger.error(f"Capture error: {error_msg}")
            # Используем invokeMethod для безопасного вызова из другого потока
            QMetaObject.invokeMethod(self, "_show_error_dialog",
                                   Qt.ConnectionType.QueuedConnection,
                                   Q_ARG(str, error_msg))
        except Exception as e:
            logger.error(f"Error handling capture error: {e}", exc_info=True)
            
    @Slot(str)
    def _show_error_dialog(self, error_msg: str):
        """Показать диалог с ошибкой"""
        try:
            self.statusBar().showMessage(f"Ошибка: {error_msg}")
            QMessageBox.critical(self, "Ошибка", str(error_msg))
            
            # Сбрасываем состояние кнопок
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            
        except Exception as e:
            logger.error(f"Error showing error dialog: {e}", exc_info=True)

    def stop_capture(self):
        """Остановка захвата пакетов"""
        try:
            if self.packet_capture:
                self.packet_capture.stop_capture()
            
            # Останавливаем таймеры
            self.check_timer.stop()
            self.restart_timer.stop()
            
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            logger.info("Packet capture stopped")
            
        except Exception as e:
            logger.error(f"Error stopping capture: {e}", exc_info=True)
            self._show_error_dialog(f"Failed to stop capture: {str(e)}")

    def show_settings(self):
        # TODO: Добавить диалог настроек
        pass

    def show_filter_dialog(self):
        """Показать диалог фильтров"""
        try:
            dialog = FilterDialog(self)
            if dialog.exec():
                new_filter = dialog.get_filter()
                if self.packet_capture:
                    self.packet_capture.set_filters([new_filter])
                    logger.info(f"Applied new filter: {new_filter}")
        except Exception as e:
            logger.error(f"Error showing filter dialog: {e}", exc_info=True)

    def apply_search(self, search_text):
        """Применение поиска к таблицам"""
        try:
            search_text = search_text.lower()
            
            # Поиск в таблице пакетов
            for row in range(self.packets_table.rowCount()):
                row_visible = False
                for col in range(self.packets_table.columnCount()):
                    item = self.packets_table.item(row, col)
                    if item and search_text in item.text().lower():
                        row_visible = True
                        break
                self.packets_table.setRowHidden(row, not row_visible)
            
            # Поиск в таблице MAC-адресов
            for row in range(self.mac_table.rowCount()):
                row_visible = False
                for col in range(self.mac_table.columnCount()):
                    item = self.mac_table.item(row, col)
                    if item and search_text in item.text().lower():
                        row_visible = True
                        break
                self.mac_table.setRowHidden(row, not row_visible)
        except Exception as e:
            logger.error(f"Error applying search: {e}", exc_info=True)

    def process_packet_queue(self):
        """Забирает пакеты из очереди PacketCapture и безопасно обновляет GUI."""
        try:
            if self.packet_capture:
                self.packet_capture.process_queued_packets()
        except Exception as e:
            logger.error(f"Error processing packet queue: {e}", exc_info=True)

    def closeEvent(self, event):
        """Обработка закрытия окна"""
        try:
            logger.info("Application closing...")
            # Останавливаем таймеры
            if hasattr(self, 'check_timer'):
                self.check_timer.stop()
            if hasattr(self, 'restart_timer'):
                self.restart_timer.stop()
            if hasattr(self, 'update_timer'):
                self.update_timer.stop()
            if hasattr(self, 'packet_queue_timer'):
                self.packet_queue_timer.stop()
            
            # Очищаем буферы
            if hasattr(self, 'packet_buffer'):
                self.packet_buffer.clear()
            if hasattr(self, 'mac_buffer'):
                self.mac_buffer.clear()
            
            # Останавливаем захват пакетов
            if hasattr(self, 'packet_capture') and self.packet_capture:
                logger.info("Stopping packet capture...")
                try:
                    self.packet_capture.stop_capture()
                    # Ждем завершения потока захвата
                    if self.packet_capture.capture_thread:
                        self.packet_capture.capture_thread.join(timeout=2.0)
                        if self.packet_capture.capture_thread.is_alive():
                            logger.warning("Capture thread did not stop gracefully")
                except Exception as e:
                    logger.error(f"Error stopping packet capture: {e}", exc_info=True)
            
            logger.info("Application closed successfully")
            event.accept()
        except Exception as e:
            logger.error(f"Error during application shutdown: {e}", exc_info=True)
            event.accept()

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        logger.critical(f"Application crashed: {e}", exc_info=True)
        sys.exit(1)
