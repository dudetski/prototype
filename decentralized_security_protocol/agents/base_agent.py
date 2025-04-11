from agents.crypto_utils import generate_key_pair, sign_message, verify_signature, get_key_str
from network.message import Message
import json
import random

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
        
        # Ключи других агентов (agent_id -> public_key)
        self.known_agents = {}
        
        # История угроз, правил и сообщений
        self.threat_history = []
        self.rules = []
        self.proposed_rules = {}  # rule_id -> rule
        self.message_history = []
        
        # Система репутации (agent_id -> score)
        self.reputation = {}
        
        # Подключенный протокол связи
        self.gossip = None
    
    def connect_to_network(self, gossip_protocol):
        """Подключает агента к сети"""
        self.gossip = gossip_protocol
        gossip_protocol.register_agent(self)
    
    def detect_threat(self, threat_data):
        """Обнаруживает угрозу и оповещает сеть"""
        threat_id = f"threat-{random.randint(1000, 9999)}"
        threat = {
            "id": threat_id,
            "data": threat_data,
            "detected_by": self.agent_id,
            "timestamp": self.get_timestamp()
        }
        
        print(f"[{self.agent_id}] Обнаружена угроза: {threat_data}")
        self.threat_history.append(threat)
        
        # Создаем сообщение об угрозе
        message = self.create_message(threat, "THREAT")
        
        # Отправляем сообщение в сеть
        if self.gossip:
            self.gossip.broadcast(message)
        
        return threat_id
    
    def propose_rule(self, rule_data, threat_id=None):
        """Предлагает новое правило безопасности"""
        rule_id = f"rule-{random.randint(1000, 9999)}"
        rule = {
            "id": rule_id,
            "data": rule_data,
            "proposed_by": self.agent_id,
            "threat_id": threat_id,
            "timestamp": self.get_timestamp(),
            "status": "PROPOSED"
        }
        
        print(f"[{self.agent_id}] Предложено правило: {rule_data}")
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
        
        print(f"[{self.agent_id}] Голосование за правило {rule_id}: {'одобрено' if approve else 'отклонено'}")
        
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
                print(f"[{self.agent_id}] Ошибка: правило {rule_id} не найдено")
                return False
        
        if rule["status"] == "APPROVED":
            print(f"[{self.agent_id}] Применяется правило: {rule['data']}")
            self.rules.append(rule)
            return True
        else:
            print(f"[{self.agent_id}] Ошибка: правило {rule['id']} не одобрено")
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
                print(f"[{self.agent_id}] Ошибка: недействительная подпись от {message.sender_id}")
                self.update_reputation(message.sender_id, -5)
                return False
        
        # Сохраняем сообщение в истории
        self.message_history.append(message)
        
        # Обрабатываем сообщение в зависимости от типа
        if message.msg_type == "AGENT_ANNOUNCE":
            # Регистрируем нового агента
            self.known_agents[message.sender_id] = message.content["public_key"]
            print(f"[{self.agent_id}] Зарегистрирован новый агент: {message.sender_id}")
            self.reputation[message.sender_id] = 50  # начальная репутация
            
        elif message.msg_type == "THREAT":
            # Обрабатываем информацию об угрозе
            threat = message.content
            print(f"[{self.agent_id}] Получена информация об угрозе от {message.sender_id}: {threat['data']}")
            self.threat_history.append(threat)
            self.update_reputation(message.sender_id, 2)
            
        elif message.msg_type == "RULE_PROPOSAL":
            # Обрабатываем предложение правила
            rule = message.content
            print(f"[{self.agent_id}] Получено предложение правила от {message.sender_id}: {rule['data']}")
            self.proposed_rules[rule["id"]] = rule
            
            # Автоматически голосуем (для демонстрации)
            # В реальной системе здесь может быть логика принятия решения
            self.vote_for_rule(rule["id"], True)
            
        elif message.msg_type == "VOTE":
            # Обрабатываем голос
            vote = message.content
            print(f"[{self.agent_id}] Получен голос от {message.sender_id} за правило {vote['rule_id']}: {vote['vote']}")
            
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
                        print(f"[{self.agent_id}] Правило {rule['id']} одобрено консенсусом")
                        self.apply_rule(rule)
                    else:
                        rule["status"] = "REJECTED"
                        print(f"[{self.agent_id}] Правило {rule['id']} отклонено консенсусом")
        
        return True
    
    def create_message(self, content, msg_type):
        """Создает подписанное сообщение"""
        message = Message(self.agent_id, content, msg_type)
        message.signature = sign_message(message.to_string(), self.private_key)
        return message
    
    def announce_presence(self):
        """Анонсирует присутствие агента в сети"""
        if not self.gossip:
            print(f"[{self.agent_id}] Ошибка: агент не подключен к сети")
            return
    
    # Создаем сообщение с информацией о себе
        content = {
            "agent_id": self.agent_id,
            "public_key": get_key_str(self.public_key)  # Use the updated function
    }
        message = self.create_message(content, "AGENT_ANNOUNCE")
    
    # Отправляем сообщение в сеть
        self.gossip.broadcast(message)
    
    def update_reputation(self, agent_id, change):
        """Обновляет репутацию агента"""
        if agent_id not in self.reputation:
            self.reputation[agent_id] = 50  # начальная репутация
        
        self.reputation[agent_id] += change
        # Ограничиваем репутацию в пределах 0-100
        self.reputation[agent_id] = max(0, min(100, self.reputation[agent_id]))
    
    def get_timestamp(self):
        """Возвращает текущую временную метку"""
        import time
        return time.time()
