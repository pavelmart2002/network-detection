#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from enum import Enum
from collections import defaultdict

class AttackType(Enum):
    DEAUTH = "Deauthentication Attack"
    BEACON_FLOOD = "Beacon Flood Attack"
    AUTH_FLOOD = "Authentication Flood"
    PROBE_FLOOD = "Probe Request Flood"
    EVIL_TWIN = "Evil Twin Attack"
    WPS_ATTACK = "WPS Brute Force"
    UNKNOWN = "Unknown Attack"

class AttackSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AttackDetector:
    def __init__(self):
        # Счетчики пакетов для каждого MAC-адреса
        self.packet_counters = defaultdict(lambda: defaultdict(int))
        # Время последнего beacon-фрейма для каждого MAC
        self.last_beacon_times = defaultdict(float)
        # История атак
        self.attack_history = []
        
        # Пороговые значения для обнаружения атак
        self.thresholds = {
            'deauth_packets': 10,  # пакетов в секунду
            'auth_packets': 50,    # пакетов в секунду
            'probe_packets': 100,  # пакетов в секунду
            'beacon_interval': 0.1 # минимальный интервал (сек)
        }

    def analyze_packet(self, packet_data):
        """Анализ пакета на предмет атак"""
        try:
            # Извлекаем данные пакета
            src_mac = packet_data.get('MAC_SA', '')
            dst_mac = packet_data.get('MAC_DA', '')
            bssid = packet_data.get('MAC_BSSID', '')
            timestamp = time.time()

            # Определяем тип пакета
            if 'Deauthentication' in packet_data.get('frame_subtype', ''):
                self._analyze_deauth(src_mac, dst_mac, timestamp)
            
            elif 'Authentication' in packet_data.get('frame_subtype', ''):
                self._analyze_auth(src_mac, timestamp)
            
            elif 'Probe Request' in packet_data.get('frame_subtype', ''):
                self._analyze_probe(src_mac, timestamp)
            
            elif 'Beacon' in packet_data.get('frame_subtype', ''):
                self._analyze_beacon(src_mac, timestamp)

            # Проверяем Evil Twin для Beacon фреймов
            if bssid and 'Beacon' in packet_data.get('frame_subtype', ''):
                essid = packet_data.get('ESSID', '')
                channel = packet_data.get('CH', '')
                encryption = packet_data.get('ENC', '')
                self._detect_evil_twin(essid, bssid, channel, encryption)

        except Exception as e:
            print(f"Error analyzing packet: {str(e)}")

    def _analyze_deauth(self, src_mac, dst_mac, timestamp):
        """Анализ пакетов деаутентификации"""
        self.packet_counters['deauth'][src_mac] += 1
        
        if self.packet_counters['deauth'][src_mac] > self.thresholds['deauth_packets']:
            self._register_attack(
                AttackType.DEAUTH,
                AttackSeverity.HIGH,
                timestamp,
                {
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'packet_count': self.packet_counters['deauth'][src_mac]
                }
            )

    def _analyze_auth(self, src_mac, timestamp):
        """Анализ пакетов аутентификации"""
        self.packet_counters['auth'][src_mac] += 1
        
        if self.packet_counters['auth'][src_mac] > self.thresholds['auth_packets']:
            self._register_attack(
                AttackType.AUTH_FLOOD,
                AttackSeverity.MEDIUM,
                timestamp,
                {
                    'src_mac': src_mac,
                    'packet_count': self.packet_counters['auth'][src_mac]
                }
            )

    def _analyze_probe(self, src_mac, timestamp):
        """Анализ probe-запросов"""
        self.packet_counters['probe'][src_mac] += 1
        
        if self.packet_counters['probe'][src_mac] > self.thresholds['probe_packets']:
            self._register_attack(
                AttackType.PROBE_FLOOD,
                AttackSeverity.LOW,
                timestamp,
                {
                    'src_mac': src_mac,
                    'packet_count': self.packet_counters['probe'][src_mac]
                }
            )

    def _analyze_beacon(self, src_mac, timestamp):
        """Анализ beacon-фреймов"""
        last_time = self.last_beacon_times[src_mac]
        if last_time > 0:
            interval = timestamp - last_time
            if interval < self.thresholds['beacon_interval']:
                self._register_attack(
                    AttackType.BEACON_FLOOD,
                    AttackSeverity.MEDIUM,
                    timestamp,
                    {
                        'src_mac': src_mac,
                        'interval': interval
                    }
                )
        self.last_beacon_times[src_mac] = timestamp

    def _detect_evil_twin(self, essid, bssid, channel, encryption):
        """Обнаружение Evil Twin атак"""
        # Поиск точек доступа с одинаковым ESSID
        for ap_bssid, ap_essid, ap_channel, ap_enc in zip(BSSIDList, ESSIDList, ChannelList, EncTypeList):
            if (ap_essid == essid and ap_bssid != bssid and 
                (ap_channel != channel or ap_enc != encryption)):
                self._register_attack(
                    AttackType.EVIL_TWIN,
                    AttackSeverity.CRITICAL,
                    time.time(),
                    {
                        'original_bssid': bssid,
                        'fake_bssid': ap_bssid,
                        'essid': essid
                    }
                )

    def _register_attack(self, attack_type, severity, timestamp, details):
        """Регистрация атаки"""
        attack = {
            'type': attack_type,
            'severity': severity,
            'timestamp': timestamp,
            'details': details
        }
        self.attack_history.append(attack)
        
        # Вывод информации об атаке
        print(f"\n[!] Attack detected: {attack_type.value}")
        print(f"    Severity: {severity.name}")
        print(f"    Details: {details}")

    def get_attack_history(self):
        """Получение истории атак"""
        return self.attack_history

    def clear_counters(self):
        """Очистка счетчиков"""
        self.packet_counters.clear()
        self.last_beacon_times.clear()
