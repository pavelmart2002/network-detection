#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import logging
import time
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
        self.demo_directions = ["Слева", "Справа", "Прямо впереди", "Северо-восток", "Северо-запад", "Юго-восток", "Юго-запад", "Сзади"]
        
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
            self.direction = 270  # 270 градусов (9:00 на часах)
        elif direction_text == "Справа":
            self.direction = 90   # 90 градусов (3:00 на часах)
        elif direction_text == "Прямо впереди":
            self.direction = 0    # 0 градусов (12:00 на часах)
        elif direction_text == "Северо-восток":
            self.direction = 45   # 45 градусов (1:30 на часах)
        elif direction_text == "Северо-запад":
            self.direction = 315  # 315 градусов (10:30 на часах)
        elif direction_text == "Юго-восток":
            self.direction = 135  # 135 градусов (4:30 на часах)
        elif direction_text == "Юго-запад":
            self.direction = 225  # 225 градусов (7:30 на часах)
        elif direction_text == "Сзади":
            self.direction = 180  # 180 градусов (6:00 на часах)
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
        
        # Логируем для отладки
        logger.info(f"Установлено направление: {direction_text}, градусы: {self.direction}")
        
        # Перерисовываем виджет
        self.update()
    
    def paintEvent(self, event):
        """Отрисовка круговой диаграммы с направлением"""
        try:
            logger.info("paintEvent вызван")
            
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Получаем размеры виджета
            width = self.width()
            height = self.height()
            
            # Вычисляем центр и радиус
            center_x = width // 2
            center_y = height // 2
            radius = min(width, height) // 2 - 40
            
            # Логируем для отладки
            logger.info(f"Размеры виджета: {width}x{height}, центр: ({center_x}, {center_y}), радиус: {radius}")
            
            # Рисуем фон
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor("#252526")))
            painter.drawRect(0, 0, width, height)
            
            # Рисуем основной круг
            painter.setPen(QPen(QColor("#555555"), 2))
            painter.setBrush(QBrush(QColor("#2D2D30")))
            painter.drawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)
            
            # Рисуем концентрические круги для индикации мощности сигнала
            for i in range(1, 4):
                r = radius * i / 3
                painter.setPen(QPen(QColor("#444444"), 1, Qt.DashLine))
                painter.drawEllipse(center_x - r, center_y - r, r * 2, r * 2)
            
            # Рисуем градусные метки по окружности
            painter.setPen(QPen(QColor("#AAAAAA"), 1))
            font = QFont()
            font.setPointSize(9)
            painter.setFont(font)
            
            # Рисуем градусные метки каждые 30 градусов
            for angle in range(0, 360, 30):
                # Преобразуем градусы в радианы
                angle_rad = math.radians(angle)
                
                # Рисуем линию от внешнего круга внутрь
                outer_x = center_x + (radius + 5) * math.sin(angle_rad)
                outer_y = center_y - (radius + 5) * math.cos(angle_rad)
                
                inner_x = center_x + (radius - 10) * math.sin(angle_rad)
                inner_y = center_y - (radius - 10) * math.cos(angle_rad)
                
                # Рисуем линию
                painter.setPen(QPen(QColor("#555555"), 1))
                painter.drawLine(int(outer_x), int(outer_y), int(inner_x), int(inner_y))
                
                # Рисуем текст с градусами
                text_x = center_x + (radius + 20) * math.sin(angle_rad) - 15
                text_y = center_y - (radius + 20) * math.cos(angle_rad) + 5
                
                painter.setPen(QPen(QColor("#AAAAAA"), 1))
                painter.drawText(int(text_x), int(text_y), f"{angle}°")
            
            # Рисуем меньшие метки каждые 10 градусов
            for angle in range(0, 360, 10):
                # Пропускаем те, которые уже нарисованы каждые 30 градусов
                if angle % 30 == 0:
                    continue
                    
                # Преобразуем градусы в радианы
                angle_rad = math.radians(angle)
                
                # Рисуем короткую линию
                outer_x = center_x + (radius + 2) * math.sin(angle_rad)
                outer_y = center_y - (radius + 2) * math.cos(angle_rad)
                
                inner_x = center_x + (radius - 5) * math.sin(angle_rad)
                inner_y = center_y - (radius - 5) * math.cos(angle_rad)
                
                # Рисуем линию
                painter.setPen(QPen(QColor("#444444"), 1))
                painter.drawLine(int(outer_x), int(outer_y), int(inner_x), int(inner_y))
            
            # Если есть направление, рисуем луч
            if self.direction is not None:
                # Преобразуем градусы в радианы
                angle_rad = math.radians(self.direction)
                
                # Вычисляем конечную точку луча
                end_x = center_x + radius * math.sin(angle_rad)
                end_y = center_y - radius * math.cos(angle_rad)
                
                # Рисуем луч с градиентом
                beam_width = 3 + int(self.signal_strength / 20)  # Ширина луча зависит от мощности сигнала
                beam_pen = QPen(QColor("#FF6E00"), beam_width)
                painter.setPen(beam_pen)
                painter.drawLine(center_x, center_y, int(end_x), int(end_y))
                
                # Рисуем наконечник луча
                arrow_size = 12
                painter.setBrush(QBrush(QColor("#FF6E00")))
                
                # Создаем треугольник для наконечника
                arrow_path = QPainterPath()
                arrow_path.moveTo(end_x, end_y)
                
                # Вычисляем точки для треугольника
                angle1 = angle_rad + math.radians(150)
                angle2 = angle_rad - math.radians(150)
                
                point1_x = end_x + arrow_size * math.sin(angle1)
                point1_y = end_y - arrow_size * math.cos(angle1)
                
                point2_x = end_x + arrow_size * math.sin(angle2)
                point2_y = end_y - arrow_size * math.cos(angle2)
                
                arrow_path.lineTo(point1_x, point1_y)
                arrow_path.lineTo(point2_x, point2_y)
                arrow_path.closeSubpath()
                
                painter.drawPath(arrow_path)
                
                # Рисуем текст с точным значением градусов в центре
                painter.setPen(QPen(QColor("#FFFFFF"), 1))
                font = QFont()
                font.setPointSize(14)
                font.setBold(True)
                painter.setFont(font)
                
                # Отображаем точное значение градусов
                angle_text = f"{self.direction}°"
                text_rect = QRect(center_x - 40, center_y + radius + 10, 80, 30)
                painter.drawText(text_rect, Qt.AlignCenter, angle_text)
                
                # Рисуем индикатор мощности сигнала
                signal_radius = 20
                signal_x = center_x - signal_radius
                signal_y = height - signal_radius * 2 - 10
                
                # Фон индикатора
                painter.setPen(QPen(QColor("#555555"), 1))
                painter.setBrush(QBrush(QColor("#252526")))
                painter.drawRect(signal_x, signal_y, signal_radius * 2, signal_radius)
                
                # Заполнение индикатора
                fill_width = int((signal_radius * 2) * self.signal_strength / 100)
                
                # Выбираем цвет в зависимости от мощности сигнала
                if self.signal_strength < 30:
                    signal_color = QColor("#FF3333")  # Красный для слабого сигнала
                elif self.signal_strength < 70:
                    signal_color = QColor("#FFCC00")  # Желтый для среднего сигнала
                else:
                    signal_color = QColor("#33CC33")  # Зеленый для сильного сигнала
                
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(signal_color))
                painter.drawRect(signal_x, signal_y, fill_width, signal_radius)
                
                # Текст с процентами
                painter.setPen(QPen(QColor("#FFFFFF"), 1))
                font.setPointSize(9)
                painter.setFont(font)
                painter.drawText(signal_x + 5, signal_y + signal_radius - 5, f"{self.signal_strength}%")
                
                # Рисуем центральную точку
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(QColor("#FF6E00")))
                painter.drawEllipse(center_x - 5, center_y - 5, 10, 10)
                
                # Рисуем пульсирующий круг вокруг центра
                pulse_size = 10 + (self.signal_strength / 10)
                pulse_opacity = 100 + int(155 * math.sin(time.time() * 5))  # Пульсация
                pulse_color = QColor("#FF6E00")
                pulse_color.setAlpha(pulse_opacity)
                
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(pulse_color))
                painter.drawEllipse(
                    center_x - pulse_size/2, 
                    center_y - pulse_size/2, 
                    pulse_size, 
                    pulse_size
                )
            
            # Рисуем рамку вокруг виджета
            painter.setPen(QPen(QColor("#555555"), 1))
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(0, 0, width - 1, height - 1)
            
        except Exception as e:
            logger.error(f"Ошибка при отрисовке: {e}", exc_info=True)
