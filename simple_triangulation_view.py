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
    
    def set_direction(self, direction):
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
            QFrame {
                border: 1px solid #555555;
            }
        """)
        
        # Создаем layout
        layout = QVBoxLayout(self)
        
        # Метка для отображения информации
        self.info_label = QLabel("Ожидание данных...")
        self.info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.info_label)
        
        # Индикатор направления
        self.direction_indicator = DirectionIndicator()
        layout.addWidget(self.direction_indicator)
        
        # Инициализация переменных
        self.source_mac = ""  # MAC-адрес источника
        self.attack_type = ""  # Тип атаки
        self.signal_strength = 0  # Мощность сигнала (0-100%)
        
        # Таймер для демонстрационного режима
        self.demo_timer = QTimer(self)
        self.demo_timer.timeout.connect(self.update_demo)
        self.demo_timer.start(2000)  # Обновление каждые 2 секунды
        
        # Флаг демонстрационного режима
        self.demo_mode = True
        self.demo_direction_index = 0
        self.demo_directions = ["Запад", "Северо-запад", "Север", "Северо-восток", 
                               "Восток", "Юго-восток", "Юг", "Юго-запад"]
        
        logger.info("SimpleTriangulationView initialized")
    
    def update_demo(self):
        """Обновление демонстрационного режима"""
        if self.demo_mode:
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
            direction_text (str): Текстовое направление
            signal_strength (int): Мощность сигнала (0-100%)
            mac (str): MAC-адрес источника
            attack_type (str): Тип атаки
        """
        # Если получены реальные данные, отключаем демо-режим
        if mac and mac != "00:11:22:33:44:55":
            self.demo_mode = False
        
        # Преобразуем направление из формата "Слева"/"Справа" в формат компаса
        compass_direction = direction_text
        if direction_text == "Слева":
            compass_direction = "Запад"
        elif direction_text == "Справа":
            compass_direction = "Восток"
        elif direction_text == "Прямо впереди":
            compass_direction = "Север"
        
        # Устанавливаем направление в индикаторе
        self.direction_indicator.set_direction(compass_direction)
        
        # Сохраняем остальные параметры
        self.signal_strength = min(100, max(0, signal_strength))
        self.source_mac = mac
        self.attack_type = attack_type
        
        # Обновляем информационную метку
        info_text = f"Источник: {self.source_mac}\n"
        info_text += f"Тип атаки: {self.attack_type}\n"
        info_text += f"Направление: {direction_text} ({compass_direction})\n"
        info_text += f"Мощность сигнала: {self.signal_strength}%"
        self.info_label.setText(info_text)
        
        # Логируем для отладки
        logger.info(f"Установлено направление: {direction_text} ({compass_direction})")
