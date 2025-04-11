from agents.crypto_utils import generate_key_pair, sign_message, verify_signature, get_key_str
from network.message import Message
import json
import random
import time
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class BaseAgent:
    def __init__(self, agent_id):
        """
        Инициализирует базового агента
        
        Args:
            agent_id: Уникальный идентификатор агента
        """
        self.agent_id = agent_id
        self.private_key, self.public_key = generate_key_pair()
        self.key_str = get_key_str(self.public_key)
        
        # Логгер для агента
        self.logger = logging.getLogger(f"Agent[{agent_id}]")
        self.logger.info(f"Инициализация агента {agent_id}")
        
        # Ключи других агентов (agent_id -> public_key)
        self.known_agents = {}
        
        # История угроз, правил и сообщений
        self.threat_history = []
        self.rules = []
        self.proposed_rules = {}  # rule_id -> rule
        self.message_history = []
        
        # Система репутации (agent_id -> score)
        self.reputation = {}
        
        # Цифровые отпечатки хостов (host_id -> fingerprint)
        self.host_fingerprints = {}
        
        # Профили поведения (host_id -> behavior_profile)
        self.behavior_profiles = {}
        
        # Исторические данные для анализа (host_id -> [events])
        self.host_events = {}
        
        # Аномалии (anomaly_id -> anomaly)
        self.detected_anomalies = {}
        
        # Подключенный протокол связи
        self.gossip = None
    
    def connect_to_network(self, gossip_protocol):
        """Подключает агента к сети"""
        self.gossip = gossip_protocol
        gossip_protocol.register_agent(self)
        self.logger.info(f"Агент подключен к сети")
    
    def detect_threat(self, threat_data):
        """Обнаруживает угрозу и оповещает сеть"""
        threat_id = f"threat-{random.randint(1000, 9999)}"
        timestamp = self.get_timestamp()
        formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        threat = {
            "id": threat_id,
            "data": threat_data,
            "detected_by": self.agent_id,
            "timestamp": timestamp,
            "formatted_time": formatted_time
        }
        
        self.logger.warning(f"Обнаружена угроза: {threat_data}")
        self.threat_history.append(threat)
        
        # Создаем сообщение об угрозе
        message = self.create_message(threat, "THREAT")
        
        # Обновляем профиль поведения, если угроза связана с конкретным хостом
        source = threat_data.get("source")
        if source:
            self.update_host_profile(source, "threat", threat_data)
        
        # Отправляем сообщение в сеть
        if self.gossip:
            self.gossip.broadcast(message)
        
        return threat_id
    
    def propose_rule(self, rule_data, threat_id=None):
        """Предлагает новое правило безопасности"""
        rule_id = f"rule-{random.randint(1000, 9999)}"
        timestamp = self.get_timestamp()
        formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        rule = {
            "id": rule_id,
            "data": rule_data,
            "proposed_by": self.agent_id,
            "threat_id": threat_id,
            "timestamp": timestamp,
            "formatted_time": formatted_time,
            "status": "PROPOSED"
        }
        
        self.logger.info(f"Предложено правило: {rule_data}")
        self.proposed_rules[rule_id] = rule
        
        # Создаем сообщение с предложением правила
        message = self.create_message(rule, "RULE_PROPOSAL")
        
        # Отправляем сообщение в сеть
        if self.gossip:
            self.gossip.broadcast(message)
        
        return rule_id
    
    def vote_for_rule(self, rule_id, approve=True):
        """Голосует за или против правила"""
        vote = {
            "rule_id": rule_id,
            "vote": "APPROVE" if approve else "REJECT",
            "voter": self.agent_id,
            "timestamp": self.get_timestamp()
        }
        
        self.logger.info(f"Голосование за правило {rule_id}: {'одобрено' if approve else 'отклонено'}")
        
        # Создаем сообщение с голосом
        message = self.create_message(vote, "VOTE")
        
        # Отправляем сообщение в сеть
        if self.gossip:
            self.gossip.broadcast(message)
        
        return vote
    
    def apply_rule(self, rule):
        """Применяет правило"""
        if isinstance(rule, str):
            rule_id = rule
            rule = self.proposed_rules.get(rule_id)
            if not rule:
                self.logger.error(f"Ошибка: правило {rule_id} не найдено")
                return False
        
        if rule["status"] == "APPROVED":
            self.logger.info(f"Применяется правило: {rule['data']}")
            self.rules.append(rule)
            
            # Если правило имеет целевой хост, обновляем его профиль
            target = rule["data"].get("target")
            if target:
                self.update_host_profile(target, "rule_applied", rule["data"])
            
            return True
        else:
            self.logger.error(f"Ошибка: правило {rule['id']} не одобрено")
            return False
    
    def receive_message(self, message):
        """Получает и обрабатывает сообщение от другого агента"""
        # Проверяем подпись, если отправитель известен
        if message.sender_id in self.known_agents:
            if not verify_signature(
                message.to_string(),
                message.signature,
                self.known_agents[message.sender_id]
            ):
                self.logger.warning(f"Недействительная подпись от {message.sender_id}")
                self.update_reputation(message.sender_id, -5)
                return False
        
        # Сохраняем сообщение в истории
        self.message_history.append(message)
        
        # Обрабатываем сообщение в зависимости от типа
        if message.msg_type == "AGENT_ANNOUNCE":
            # Регистрируем нового агента
            self.known_agents[message.sender_id] = message.content["public_key"]
            self.logger.info(f"Зарегистрирован новый агент: {message.sender_id}")
            self.reputation[message.sender_id] = 50  # начальная репутация
            
        elif message.msg_type == "THREAT":
            # Обрабатываем информацию об угрозе
            threat = message.content
            self.logger.warning(f"Получена информация об угрозе от {message.sender_id}: {threat['data']}")
            self.threat_history.append(threat)
            self.update_reputation(message.sender_id, 2)
            
            # Обновляем профиль поведения, если угроза связана с конкретным хостом
            source = threat["data"].get("source")
            if source:
                self.update_host_profile(source, "threat_reported", threat["data"])
            
        elif message.msg_type == "RULE_PROPOSAL":
            # Обрабатываем предложение правила
            rule = message.content
            self.logger.info(f"Получено предложение правила от {message.sender_id}: {rule['data']}")
            self.proposed_rules[rule["id"]] = rule
            
            # Автоматически голосуем (для демонстрации)
            # В реальной системе здесь может быть логика принятия решения
            self.vote_for_rule(rule["id"], True)
            
        elif message.msg_type == "VOTE":
            # Обрабатываем голос
            vote = message.content
            self.logger.info(f"Получен голос от {message.sender_id} за правило {vote['rule_id']}: {vote['vote']}")
            
            # Обновляем правило, если оно у нас есть
            if vote["rule_id"] in self.proposed_rules:
                rule = self.proposed_rules[vote["rule_id"]]
                if "votes" not in rule:
                    rule["votes"] = []
                rule["votes"].append(vote)
                
                # Проверяем, достигнут ли консенсус
                if len(rule["votes"]) >= len(self.known_agents) / 2:
                    approvals = sum(1 for v in rule["votes"] if v["vote"] == "APPROVE")
                    if approvals > len(rule["votes"]) / 2:
                        rule["status"] = "APPROVED"
                        self.logger.info(f"Правило {rule['id']} одобрено консенсусом")
                        self.apply_rule(rule)
                    else:
                        rule["status"] = "REJECTED"
                        self.logger.info(f"Правило {rule['id']} отклонено консенсусом")
        
        elif message.msg_type == "HOST_FINGERPRINT":
            # Получаем информацию об отпечатке хоста
            fingerprint = message.content
            host_id = fingerprint["host_id"]
            self.logger.info(f"Получен цифровой отпечаток хоста {host_id}")
            self.host_fingerprints[host_id] = fingerprint
            
        elif message.msg_type == "ANOMALY_DETECTED":
            # Получаем информацию об аномалии
            anomaly = message.content
            self.logger.warning(f"Получено уведомление об аномалии от {message.sender_id}: {anomaly['description']}")
            self.detected_anomalies[anomaly["id"]] = anomaly
            
            # Автоматическое создание правила при обнаружении аномалии
            if anomaly.get("severity", 0) > 70:  # Если серьезная аномалия
                self.propose_rule_for_anomaly(anomaly)
        
        return True
    
    def create_message(self, content, msg_type):
        """Создает подписанное сообщение"""
        message = Message(self.agent_id, content, msg_type)
        message.signature = sign_message(message.to_string(), self.private_key)
        return message
    
    def announce_presence(self):
        """Анонсирует присутствие агента в сети"""
        if not self.gossip:
            self.logger.error("Ошибка: агент не подключен к сети")
            return
    
        # Создаем сообщение с информацией о себе
        content = {
            "agent_id": self.agent_id,
            "public_key": get_key_str(self.public_key)
        }
        message = self.create_message(content, "AGENT_ANNOUNCE")
    
        # Отправляем сообщение в сеть
        self.gossip.broadcast(message)
        self.logger.info("Присутствие агента анонсировано в сети")
    
    def update_reputation(self, agent_id, change):
        """Обновляет репутацию агента"""
        if agent_id not in self.reputation:
            self.reputation[agent_id] = 50  # начальная репутация
        
        old_reputation = self.reputation[agent_id]
        self.reputation[agent_id] += change
        # Ограничиваем репутацию в пределах 0-100
        self.reputation[agent_id] = max(0, min(100, self.reputation[agent_id]))
        
        if change != 0:
            self.logger.info(f"Репутация агента {agent_id} изменена с {old_reputation} на {self.reputation[agent_id]}")
    
    def get_timestamp(self):
        """Возвращает текущую временную метку"""
        return time.time()
    
    def create_host_fingerprint(self, host_id, data):
        """Создает цифровой отпечаток хоста"""
        fingerprint = {
            "host_id": host_id,
            "created_by": self.agent_id,
            "timestamp": self.get_timestamp(),
            "data": data,
            "id": f"fingerprint-{random.randint(1000, 9999)}"
        }
        
        self.logger.info(f"Создан цифровой отпечаток для хоста {host_id}")
        self.host_fingerprints[host_id] = fingerprint
        
        # Создаем сообщение с отпечатком
        message = self.create_message(fingerprint, "HOST_FINGERPRINT")
        
        # Отправляем сообщение в сеть
        if self.gossip:
            self.gossip.broadcast(message)
        
        return fingerprint
    
    def update_host_profile(self, host_id, event_type, data):
        """Обновляет профиль поведения хоста"""
        if host_id not in self.host_events:
            self.host_events[host_id] = []
        
        event = {
            "type": event_type,
            "data": data,
            "timestamp": self.get_timestamp()
        }
        
        self.host_events[host_id].append(event)
        self.logger.debug(f"Обновлен профиль хоста {host_id}: {event_type}")
        
        # Создаем или обновляем профиль поведения
        self._update_behavior_profile(host_id)
        
        # Проверяем на аномалии
        self.check_for_anomalies(host_id)
    
    def _update_behavior_profile(self, host_id):
        """Обновляет профиль поведения на основе истории событий"""
        if host_id not in self.host_events or not self.host_events[host_id]:
            return
        
        events = self.host_events[host_id]
        
        # Создаем базовый профиль, если его еще нет
        if host_id not in self.behavior_profiles:
            self.behavior_profiles[host_id] = {
                "event_counts": {},
                "avg_interval": 0,
                "last_update": self.get_timestamp(),
                "connections": {},
                "protocols": {},
                "activity_hours": [0] * 24,
                "reputation_score": 50
            }
        
        profile = self.behavior_profiles[host_id]
        
        # Обновляем счетчики событий
        for event in events:
            event_type = event["type"]
            if event_type not in profile["event_counts"]:
                profile["event_counts"][event_type] = 0
            profile["event_counts"][event_type] += 1
            
            # Обновляем данные о соединениях
            if "source" in event["data"] and "target" in event["data"]:
                source = event["data"]["source"]
                target = event["data"]["target"]
                connection = f"{source}->{target}"
                
                if connection not in profile["connections"]:
                    profile["connections"][connection] = 0
                profile["connections"][connection] += 1
            
            # Обновляем данные о протоколах
            if "protocol" in event["data"]:
                protocol = event["data"]["protocol"]
                if protocol not in profile["protocols"]:
                    profile["protocols"][protocol] = 0
                profile["protocols"][protocol] += 1
            
            # Обновляем активность по часам
            event_time = datetime.fromtimestamp(event["timestamp"])
            hour = event_time.hour
            profile["activity_hours"][hour] += 1
        
        # Обновляем среднее время между событиями
        if len(events) > 1:
            timestamps = [e["timestamp"] for e in events]
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if intervals:
                profile["avg_interval"] = sum(intervals) / len(intervals)
        
        # Обновляем репутацию на основе событий
        threat_count = profile["event_counts"].get("threat", 0) + profile["event_counts"].get("threat_reported", 0)
        total_events = sum(profile["event_counts"].values())
        
        if total_events > 0:
            threat_ratio = threat_count / total_events
            # Снижаем репутацию при высоком соотношении угроз
            if threat_ratio > 0.3:
                profile["reputation_score"] = max(0, profile["reputation_score"] - 10)
            elif threat_ratio < 0.05 and total_events > 10:
                profile["reputation_score"] = min(100, profile["reputation_score"] + 5)
        
        profile["last_update"] = self.get_timestamp()
        self.logger.debug(f"Обновлен поведенческий профиль хоста {host_id}")
    
    def check_for_anomalies(self, host_id):
        """Проверяет аномалии в поведении хоста"""
        if host_id not in self.behavior_profiles:
            return
        
        profile = self.behavior_profiles[host_id]
        events = self.host_events.get(host_id, [])
        
        if not events or len(events) < 5:
            return  # Недостаточно данных для анализа
        
        anomalies = []
        
        # Проверка на внезапное увеличение частоты событий
        recent_events = [e for e in events if e["timestamp"] > self.get_timestamp() - 3600]  # события за последний час
        if len(recent_events) > 0:
            recent_rate = len(recent_events) / 3600
            all_rate = len(events) / (self.get_timestamp() - events[0]["timestamp"])
            
            if recent_rate > all_rate * 3 and len(recent_events) > 10:
                anomaly = {
                    "id": f"anomaly-{random.randint(1000, 9999)}",
                    "host_id": host_id,
                    "type": "activity_spike",
                    "description": f"Внезапный всплеск активности хоста {host_id}",
                    "severity": 70,
                    "detected_at": self.get_timestamp(),
                    "details": {
                        "recent_rate": recent_rate,
                        "average_rate": all_rate,
                        "ratio": recent_rate / all_rate if all_rate > 0 else "∞"
                    }
                }
                anomalies.append(anomaly)
        
        # Проверка на необычное время активности
        event_time = datetime.fromtimestamp(events[-1]["timestamp"])
        hour = event_time.hour
        
        if profile["activity_hours"][hour] <= 1 and sum(profile["activity_hours"]) > 24:
            anomaly = {
                "id": f"anomaly-{random.randint(1000, 9999)}",
                "host_id": host_id,
                "type": "unusual_time",
                "description": f"Необычное время активности хоста {host_id} ({hour}:00)",
                "severity": 50,
                "detected_at": self.get_timestamp(),
                "details": {
                    "hour": hour,
                    "normal_activity_hours": [i for i, count in enumerate(profile["activity_hours"]) if count > 0]
                }
            }
            anomalies.append(anomaly)
        
        # Проверка на новые соединения
        if events[-1]["type"] == "connection" and "source" in events[-1]["data"] and "target" in events[-1]["data"]:
            source = events[-1]["data"]["source"]
            target = events[-1]["data"]["target"]
            connection = f"{source}->{target}"
            
            if connection not in profile["connections"] or profile["connections"][connection] <= 1:
                anomaly = {
                    "id": f"anomaly-{random.randint(1000, 9999)}",
                    "host_id": host_id,
                    "type": "new_connection",
                    "description": f"Обнаружено новое соединение {connection}",
                    "severity": 30,
                    "detected_at": self.get_timestamp(),
                    "details": {
                        "connection": connection,
                        "source": source,
                        "target": target
                    }
                }
                anomalies.append(anomaly)
        
        # Обрабатываем найденные аномалии
        for anomaly in anomalies:
            self.detected_anomalies[anomaly["id"]] = anomaly
            self.logger.warning(f"Обнаружена аномалия: {anomaly['description']}, тяжесть: {anomaly['severity']}")
            
            # Создаем сообщение об аномалии
            message = self.create_message(anomaly, "ANOMALY_DETECTED")
            
            # Отправляем сообщение в сеть
            if self.gossip:
                self.gossip.broadcast(message)
            
            # Для серьезных аномалий предлагаем правило
            if anomaly["severity"] > 70:
                self.propose_rule_for_anomaly(anomaly)
    
    def propose_rule_for_anomaly(self, anomaly):
        """Предлагает правило на основе обнаруженной аномалии"""
        host_id = anomaly["host_id"]
        
        # Создаем правило в зависимости от типа аномалии
        if anomaly["type"] == "activity_spike":
            rule_data = {
                "type": "RATE_LIMIT",
                "target": host_id,
                "action": "THROTTLE",
                "duration": 1800,  # 30 минут
                "threshold": anomaly["details"]["average_rate"] * 1.5,  # 150% от средней скорости
                "description": f"Ограничение скорости для хоста {host_id} из-за аномальной активности"
            }
        elif anomaly["type"] == "unusual_time":
            rule_data = {
                "type": "MONITOR",
                "target": host_id,
                "action": "ALERT",
                "duration": 3600,  # 1 час
                "description": f"Усиленный мониторинг хоста {host_id} из-за активности в необычное время"
            }
        elif anomaly["type"] == "new_connection" and anomaly["severity"] > 50:
            rule_data = {
                "type": "BLOCK_CONNECTION",
                "target": anomaly["details"]["source"],
                "destination": anomaly["details"]["target"],
                "action": "BLOCK",
                "duration": 1800,  # 30 минут
                "description": f"Блокировка нового подозрительного соединения {anomaly['details']['connection']}"
            }
        else:
            rule_data = {
                "type": "MONITOR",
                "target": host_id,
                "action": "LOG",
                "duration": 3600,  # 1 час
                "description": f"Мониторинг хоста {host_id} из-за обнаруженной аномалии типа {anomaly['type']}"
            }
        
        self.logger.info(f"Предлагается правило на основе аномалии: {rule_data}")
        return self.propose_rule(rule_data)
    
    def export_logs(self, filename=None):
        """Экспортирует логи для анализа"""
        logs = {
            "agent_id": self.agent_id,
            "timestamp": self.get_timestamp(),
            "threats": self.threat_history,
            "rules": self.rules,
            "anomalies": self.detected_anomalies,
            "host_profiles": self.behavior_profiles
        }
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(logs, f, indent=2)
                self.logger.info(f"Логи экспортированы в файл {filename}")
        
        return logs
