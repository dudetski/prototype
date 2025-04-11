#!/usr/bin/env python3
import os
import sys
import time
import signal
import threading
from agents.base_agent import BaseAgent
from agents.learning_agent import LearningAgent
from decentralized_security_protocol.network.gossip_protocol import GossipProtocol
from decentralized_security_protocol.network.consensus import Consensus
from decentralized_security_protocol.network.transport import NetworkTransport
from rules.rule_engine import RuleEngine

running = True

def signal_handler(sig, frame):
    global running
    print("[SHUTDOWN] Остановка службы...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def receive_message(self, message):
    """Получает и обрабатывает сообщение от другого агента"""
    print(f"[{self.agent_id}] Получено сообщение: {message.to_string()} от {message.sender_id}")
    
    # Проверяем подпись, если отправитель известен
    if message.sender_id in self.known_agents:
        print(f"[{self.agent_id}] Проверка подписи от {message.sender_id}")
        if not verify_signature(
            message.to_string(),
            message.signature,
            self.known_agents[message.sender_id]
        ):
            print(f"[{self.agent_id}] Ошибка: недействительная подпись от {message.sender_id}")
            self.update_reputation(message.sender_id, -5)
            return False
        
def setup_agents():
    agents = {}
    for i in range(5):
        agent_id = f"agent-{i+1}"
        if i % 2 == 0:
            agents[agent_id] = LearningAgent(agent_id)
        else:
            agents[agent_id] = BaseAgent(agent_id)
        agents[agent_id].connect_to_network(gossip)
        agents[agent_id].announce_presence()
        time.sleep(0.2)
    return agents

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
    
    for agent_id, ag in agents.items():
        if ag.agent_id != agent.agent_id:
            approve = True  # по умолчанию все согласны
            ag.vote_for_rule(rule_id, approve)
            consensus.register_vote(rule_id, ag.agent_id, "APPROVE", ag.reputation.get(agent.agent_id, 50))

    status, _ = consensus.check_consensus(rule_id, len(agents))
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

    agents = setup_agents()

    print("[READY] Протокол запущен. Ожидание входящих угроз...")

    def threat_feed():
        while running:
            time.sleep(10)
            threat = {
                "type": "DDoS",
                "severity": "high",
                "source": f"10.0.0.{random.randint(2, 250)}",
                "target": "web-server",
                "timestamp": time.time()
            }
            initiator = random.choice(list(agents.values()))
            process_threat(initiator, threat)

    import random
    thread = threading.Thread(target=threat_feed)
    thread.start()

    while running:
        time.sleep(1)

    transport.stop()
    print("[EXIT] Служба завершена.")
