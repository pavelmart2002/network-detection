#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGridLayout, QFrame
from PySide6.QtGui import QColor, QPalette
from PySide6.QtCore import Qt, QTimer

# Настройка логирования
logger = logging.getLogger("simple_triangulation_view")

class DirectionIndicator(QFrame):
    """Простой индикатор направления, использующий цветные блоки"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(300, 300)
        self.setFrameShape(QFrame.Box)
        self.setFrameShadow(QFrame.Sunken)
        
        # Создаем сетку 3x3 для индикаторов направления
        self.grid_layout = QGridLayout(self)
        self.grid_layout.setSpacing(5)
        
        # Создаем 9 блоков для индикации направления
        self.direction_blocks = {}
        directions = [
            ("Северо-запад", 0, 0), ("Север", 0, 1), ("Северо-восток", 0, 2),
            ("Запад", 1, 0), ("Центр", 1, 1), ("Восток", 1, 2),
            ("Юго-запад", 2, 0), ("Юг", 2, 1), ("Юго-восток", 2, 2)
        ]
        
        for name, row, col in directions:
            block = QFrame()
            block.setFrameShape(QFrame.Box)
            block.setFrameShadow(QFrame.Plain)
            block.setMinimumSize(80, 80)
            block.setAutoFillBackground(True)
            
            # Устанавливаем темный цвет фона
            palette = block.palette()
            palette.setColor(QPalette.Window, QColor("#252526"))
            block.setPalette(palette)
            
            # Добавляем метку с названием направления
            layout = QVBoxLayout(block)
            label = QLabel(name)
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            
            self.grid_layout.addWidget(block, row, col)
            self.direction_blocks[name] = block
        
        # Текущее активное направление
        self.active_direction = None
    
    def set_direction(self, direction, signal_strength=50):
        """Установка активного направления"""
        # Сбрасываем предыдущее активное направление
        if self.active_direction and self.active_direction in self.direction_blocks:
            palette = self.direction_blocks[self.active_direction].palette()
            palette.setColor(QPalette.Window, QColor("#252526"))
            self.direction_blocks[self.active_direction].setPalette(palette)
        
        # Устанавливаем новое активное направление
        if direction in self.direction_blocks:
            self.active_direction = direction
            palette = self.direction_blocks[direction].palette()
            palette.setColor(QPalette.Window, QColor("#FF6E00"))
            self.direction_blocks[direction].setPalette(palette)
            
            logger.info(f"Установлено направление: {direction}")
        else:
            logger.warning(f"Неизвестное направление: {direction}")

class SimpleTriangulationView(QWidget):
    """Простой виджет для отображения направления на источник атаки"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Пеленгация источника атаки")
        self.setMinimumSize(400, 400)
        
        # Темная тема с оранжевыми акцентами
        self.setStyleSheet("""
            QWidget {
                background-color: #2D2D30;
                color: #E0E0E0;
            }
            QLabel {
                color: #E0E0E0;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        
        # Инициализация переменных
        self.direction = None  # Направление на источник
        self.direction_degrees = None  # Направление в градусах
        self.signal_strength = 0  # Мощность сигнала (0-100%)
        self.source_mac = ""  # MAC-адрес источника
        self.attack_type = ""  # Тип атаки
        
        # Создаем layout
        layout = QVBoxLayout(self)
        
        # Метка для отображения информации
        self.info_label = QLabel("Ожидание данных...")
        self.info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.info_label)
        
        # Виджет для отображения направления
        self.direction_indicator = DirectionIndicator()
        layout.addWidget(self.direction_indicator)
        
        # Метка для отображения градусов
        self.degrees_label = QLabel("")
        self.degrees_label.setAlignment(Qt.AlignCenter)
        self.degrees_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FF6E00;")
        layout.addWidget(self.degrees_label)
        
        # Таймер для обновления
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_view)
        self.update_timer.start(100)  # Обновление каждые 100 мс
        
        # Таймер для демонстрационного режима
        self.demo_timer = QTimer(self)
        self.demo_timer.timeout.connect(self.update_demo)
        self.demo_timer.start(2000)  # Обновление каждые 2 секунды
        
        # Флаг демонстрационного режима
        self.demo_mode = True
        self.demo_direction_index = 0
        self.demo_directions = ["Слева", "Справа", "Прямо впереди", "Северо-восток", "Северо-запад", "Юго-восток", "Юго-запад", "Сзади"]
        
        logger.info("SimpleTriangulationView initialized")
    
    def update_view(self):
        """Обновление отображения"""
        self.update()  # Перерисовка виджета
    
    def update_demo(self):
        """Обновление демонстрационного режима"""
        if self.demo_mode and not self.direction:
            # Циклически меняем направление
            direction = self.demo_directions[self.demo_direction_index]
            self.demo_direction_index = (self.demo_direction_index + 1) % len(self.demo_directions)
            
            # Устанавливаем демонстрационные данные
            self.set_direction(
                direction,
                signal_strength=70,
                mac="00:11:22:33:44:55",
                attack_type="Демонстрационный режим"
            )
            
            logger.info(f"Демонстрационный режим: направление = {direction}")
    
    def set_direction(self, direction_text, signal_strength=50, mac="", attack_type=""):
        """Установка направления на источник
        
        Args:
            direction_text (str): Текстовое направление ("Слева", "Справа", "Прямо впереди" и т.д.)
            signal_strength (int): Мощность сигнала (0-100%)
            mac (str): MAC-адрес источника
            attack_type (str): Тип атаки
        """
        # Если получены реальные данные, отключаем демо-режим
        if mac and mac != "00:11:22:33:44:55":
            self.demo_mode = False
        
        # Сохраняем направление
        self.direction = direction_text
        
        # Преобразуем текстовое направление в градусы
        if direction_text == "Слева":
            self.direction_degrees = 270  # 270 градусов (9:00 на часах)
        elif direction_text == "Справа":
            self.direction_degrees = 90   # 90 градусов (3:00 на часах)
        elif direction_text == "Прямо впереди":
            self.direction_degrees = 0    # 0 градусов (12:00 на часах)
        elif direction_text == "Северо-восток":
            self.direction_degrees = 45   # 45 градусов (1:30 на часах)
        elif direction_text == "Северо-запад":
            self.direction_degrees = 315  # 315 градусов (10:30 на часах)
        elif direction_text == "Юго-восток":
            self.direction_degrees = 135  # 135 градусов (4:30 на часах)
        elif direction_text == "Юго-запад":
            self.direction_degrees = 225  # 225 градусов (7:30 на часах)
        elif direction_text == "Сзади":
            self.direction_degrees = 180  # 180 градусов (6:00 на часах)
        else:
            self.direction_degrees = None
        
        # Сохраняем остальные параметры
        self.signal_strength = min(100, max(0, signal_strength))
        self.source_mac = mac
        self.attack_type = attack_type
        
        # Обновляем информационную метку
        if self.direction is not None:
            info_text = f"Источник: {self.source_mac}\n"
            info_text += f"Тип атаки: {self.attack_type}\n"
            info_text += f"Направление: {self.direction}\n"
            info_text += f"Мощность сигнала: {self.signal_strength}%"
            self.info_label.setText(info_text)
        else:
            self.info_label.setText("Ожидание данных...")
        
        # Обновляем метку с градусами
        if self.direction_degrees is not None:
            self.degrees_label.setText(f"{self.direction_degrees}°")
        else:
            self.degrees_label.setText("")
        
        # Обновляем индикатор направления
        self.direction_indicator.set_direction(direction_text, self.signal_strength)
        
        # Логируем для отладки
        logger.info(f"Установлено направление: {direction_text}, градусы: {self.direction_degrees}")
        
        # Перерисовываем виджет
        self.update()
