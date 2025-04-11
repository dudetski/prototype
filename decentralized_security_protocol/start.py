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
from agents.crypto_utils import verify_signature

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
            initiator = next(iter(agents.values()))
            process_threat(initiator, threat)

    thread = threading.Thread(target=threat_feed, daemon=True)
    thread.start()

    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        print("\n[SHUTDOWN] Завершение работы по запросу пользователя...")

    transport.stop()
    print("[EXIT] Служба завершена.")
