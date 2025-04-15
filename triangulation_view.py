#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import logging
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QPainterPath, QFont
from PySide6.QtCore import Qt, QTimer, QRect, QPoint, Signal, Slot

# Настройка логирования
logger = logging.getLogger("triangulation_view")

class TriangulationView(QWidget):
    """Виджет для отображения направления на источник атаки"""
    
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
        self.direction = None  # Направление на источник (градусы)
        self.signal_strength = 0  # Мощность сигнала (0-100%)
        self.source_mac = ""  # MAC-адрес источника
        self.attack_type = ""  # Тип атаки
        
        # Создаем layout
        layout = QVBoxLayout(self)
        
        # Метка для отображения информации
        self.info_label = QLabel("Ожидание данных...")
        self.info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.info_label)
        
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
        self.demo_directions = ["Слева", "Прямо впереди", "Справа"]
        
        logger.info("TriangulationView initialized")
    
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
            direction_text (str): Текстовое направление ("Слева", "Справа", "Прямо впереди")
            signal_strength (int): Мощность сигнала (0-100%)
            mac (str): MAC-адрес источника
            attack_type (str): Тип атаки
        """
        # Если получены реальные данные, отключаем демо-режим
        if mac and mac != "00:11:22:33:44:55":
            self.demo_mode = False
        
        # Преобразуем текстовое направление в градусы
        if direction_text == "Слева":
            self.direction = 315  # 315 градусов (10:30 на часах)
        elif direction_text == "Справа":
            self.direction = 45   # 45 градусов (1:30 на часах)
        elif direction_text == "Прямо впереди":
            self.direction = 0    # 0 градусов (12:00 на часах)
        else:
            self.direction = None
        
        # Сохраняем остальные параметры
        self.signal_strength = min(100, max(0, signal_strength))
        self.source_mac = mac
        self.attack_type = attack_type
        
        # Обновляем информационную метку
        if self.direction is not None:
            info_text = f"Источник: {self.source_mac}\n"
            info_text += f"Тип атаки: {self.attack_type}\n"
            info_text += f"Направление: {direction_text}\n"
            info_text += f"Мощность сигнала: {self.signal_strength}%"
            self.info_label.setText(info_text)
        else:
            self.info_label.setText("Ожидание данных...")
        
        # Перерисовываем виджет
        self.update()
    
    def paintEvent(self, event):
        """Отрисовка круговой диаграммы с направлением"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Получаем размеры виджета
        width = self.width()
        height = self.height()
        
        # Вычисляем центр и радиус
        center_x = width // 2
        center_y = height // 2
        radius = min(width, height) // 2 - 40
        
        # Рисуем круг
        painter.setPen(QPen(QColor("#555555"), 2))
        painter.setBrush(QBrush(QColor("#252526")))
        painter.drawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)
        
        # Рисуем метки направлений
        painter.setPen(QPen(QColor("#AAAAAA"), 1))
        font = QFont()
        font.setPointSize(10)
        painter.setFont(font)
        
        # Север (0 градусов)
        painter.drawLine(center_x, center_y - radius, center_x, center_y - radius + 15)
        painter.drawText(center_x - 5, center_y - radius - 5, "С")
        
        # Восток (90 градусов)
        painter.drawLine(center_x + radius, center_y, center_x + radius - 15, center_y)
        painter.drawText(center_x + radius + 5, center_y + 5, "В")
        
        # Юг (180 градусов)
        painter.drawLine(center_x, center_y + radius, center_x, center_y + radius - 15)
        painter.drawText(center_x - 5, center_y + radius + 15, "Ю")
        
        # Запад (270 градусов)
        painter.drawLine(center_x - radius, center_y, center_x - radius + 15, center_y)
        painter.drawText(center_x - radius - 15, center_y + 5, "З")
        
        # Рисуем концентрические круги для индикации мощности сигнала
        for i in range(1, 4):
            r = radius * i / 3
            painter.setPen(QPen(QColor("#444444"), 1, Qt.DashLine))
            painter.drawEllipse(center_x - r, center_y - r, r * 2, r * 2)
        
        # Если есть направление, рисуем луч
        if self.direction is not None:
            # Преобразуем градусы в радианы (0 градусов - север)
            angle_rad = math.radians(self.direction)
            
            # Вычисляем конечную точку луча
            end_x = center_x + radius * math.sin(angle_rad)
            end_y = center_y - radius * math.cos(angle_rad)
            
            # Рисуем луч
            beam_pen = QPen(QColor("#FF6E00"), 3)
            painter.setPen(beam_pen)
            painter.drawLine(center_x, center_y, int(end_x), int(end_y))
            
            # Рисуем наконечник луча
            arrow_size = 10
            painter.setBrush(QBrush(QColor("#FF6E00")))
            
            # Создаем треугольник для наконечника
            path = QPainterPath()
            path.moveTo(end_x, end_y)
            
            # Вычисляем точки треугольника
            angle1 = angle_rad + math.radians(150)
            angle2 = angle_rad - math.radians(150)
            
            point1_x = end_x + arrow_size * math.sin(angle1)
            point1_y = end_y - arrow_size * math.cos(angle1)
            
            point2_x = end_x + arrow_size * math.sin(angle2)
            point2_y = end_y - arrow_size * math.cos(angle2)
            
            path.lineTo(point1_x, point1_y)
            path.lineTo(point2_x, point2_y)
            path.closeSubpath()
            
            painter.drawPath(path)
            
            # Рисуем точку в центре
            painter.setBrush(QBrush(QColor("#FF6E00")))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(center_x - 5, center_y - 5, 10, 10)
        
        # Завершаем рисование
        painter.end()
