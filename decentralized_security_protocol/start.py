#!/usr/bin/env python3
import os
import sys
import time
import signal
import threading
import random
from agents.base_agent import BaseAgent
from agents.learning_agent import LearningAgent
from network.gossip_protocol import GossipProtocol
from network.consensus import Consensus
from network.transport import NetworkTransport
from rules.rule_engine import RuleEngine

running = True

def signal_handler(sig, frame):
    global running
    print("[SHUTDOWN] Остановка службы...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def setup_agent():
    agent_id = f"agent-{random.randint(1000, 9999)}"
    agent = LearningAgent(agent_id)
    agent.connect_to_network(gossip)
    agent.announce_presence()

    # Ожидаем 2 секунды, чтобы собрать других агентов
    time.sleep(2)

    known = agent.known_agents.keys()
    if known:
        print(f"[DISCOVERY] Найдено {len(known)} агентов: {list(known)}")
    else:
        print("[DISCOVERY] Агентов не найдено. Работаем автономно.")

    return {agent_id: agent}

def search_for_agents(agent):
    while True:
        print("Поиск других агентов...")
        time.sleep(2)
        known = agent.known_agents.keys()
        if known:
            print(f"[DISCOVERY] Найдено {len(known)} агентов: {list(known)}")
            break
        else:
            print("[DISCOVERY] Агентов не найдено. Продолжаем поиск...")
            response = input("Продолжить поиск? (yes/no): ")
            if response.lower() != "yes":
                break

def process_threat(agent, threat_data):
    print(f"[THREAT] Агент {agent.agent_id} обнаруживает угрозу")
    threat_id = agent.detect_threat(threat_data)
    time.sleep(0.5)

    if isinstance(agent, LearningAgent):
        rule_id = agent.suggest_rule(threat_id)
    else:
        rule_data = {
            "type": "BLOCK",
            "target": threat_data["source"],
            "action": "BLOCK",
            "duration": 3600,
            "description": "Автоблокировка источника угрозы"
        }
        rule_id = agent.propose_rule(rule_data, threat_id)

    if not agent.known_agents:
        print("[MODE] Автономный режим. Применение правила без голосования.")
        rule = agent.proposed_rules.get(rule_id)
        if rule:
            rule["status"] = "APPROVED"
            rule_engine.register_rule(rule)
            agent.apply_rule(rule_id)
            rule_engine.apply_rule(rule_id)
        else:
            print(f"[ERROR] Правило {rule_id} не найдено")
    else:
        print("[MODE] Сетевой режим. Голосование агентов.")
        for agent_id in agent.known_agents:
            ag = agents.get(agent_id)
            if ag and ag.agent_id != agent.agent_id:
                ag.vote_for_rule(rule_id, approve=True)
                consensus.register_vote(rule_id, ag.agent_id, "APPROVE", ag.reputation.get(agent.agent_id, 50))

        status, _ = consensus.check_consensus(rule_id, len(agent.known_agents) + 1)
        if status == "APPROVED":
            print(f"[RULE] Правило {rule_id} одобрено, применяется...")
            rule = agent.proposed_rules.get(rule_id)
            if rule:
                rule_engine.register_rule(rule)
                for ag in agents.values():
                    ag.apply_rule(rule_id)
                rule_engine.apply_rule(rule_id)
            else:
                print(f"[ERROR] Правило {rule_id} не найдено у инициатора")

if __name__ == '__main__':
    print("[INIT] Запуск службы протокола безопасности...")

    transport = NetworkTransport(host='127.0.0.1', port=9001)
    transport.start_server()
    gossip = GossipProtocol()
    gossip.connect_to_network_transport(transport)
    consensus = Consensus()
    rule_engine = RuleEngine()

    agents = setup_agent()

    print("[READY] Агент готов. Ожидание угроз...")

    search_for_agents(next(iter(agents.values())))

    def threat_feed():
        while running:
            time.sleep(10)
            threat = {
            "agent_id": self.agent_id,
            "public_key": self.key_str
        }
        message = self.create_message(content, "AGENT_ANNOUNCE")
        
        # Отправляем сообщение в сеть
        self.gossip.broadcast(message)
        self.logger.info(f"Агент {self.agent_id} анонсировал свое присутствие в сети")

    def update_host_profile(self, host_id, event_type, event_data):
        """Обновляет профиль поведения хоста"""
        if host_id not in self.behavior_profiles:
            self.behavior_profiles[host_id] = []
        
        self.behavior_profiles[host_id].append({
            "event_type": event_type,
            "event_data": event_data,
            "timestamp": self.get_timestamp()
        })
        self.logger.info(f"Обновлен профиль поведения для хоста {host_id}: {event_type}")

    def get_timestamp(self):
        """Возвращает текущий временной штамп"""
        return int(time.time())

    def update_reputation(self, agent_id, score_change):
        """Обновляет репутацию агента"""
        if agent_id not in self.reputation:
            self.reputation[agent_id] = 50  # начальная репутация
        self.reputation[agent_id] += score_change
        self.logger.info(f"Обновлена репутация агента {agent_id}: {self.reputation[agent_id]}")

# Пример использования
if __name__ == "__main__":
    agent = BaseAgent("agent-1")
    # Здесь можно добавить логику для подключения к сети и обработки сообщений