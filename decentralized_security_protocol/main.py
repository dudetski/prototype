#!/usr/bin/env python3
from agents.base_agent import BaseAgent
from agents.learning_agent import LearningAgent
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from decentralized_security_protocol.network.gossip_protocol import GossipProtocol
from decentralized_security_protocol.network.consensus import Consensus
from decentralized_security_protocol.network.transport import NetworkTransport
from rules.rule_engine import RuleEngine
import time
import random
import json

def simulate_threat(agent, threat_type="DDoS"):
    """Симулирует обнаружение угрозы"""
    sources = ["192.168.1.100", "10.0.0.25", "172.16.10.5", "8.8.8.8"]
    targets = ["api-server", "database", "web-frontend", "auth-service"]
    
    threat_data = {
        "type": threat_type,
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "source": random.choice(sources),
        "target": random.choice(targets),
        "timestamp": time.time()
    }
    
    return agent.detect_threat(threat_data)

def main():
    print("Запуск симуляции децентрализованного протокола безопасности...")
    
    # Инициализируем компоненты системы
    try:
        transport = NetworkTransport(host='127.0.0.1', port=9001)
        transport.start_server()
        print(f"[DEBUG] Network transport started successfully on port 9001")
    except Exception as e:
        print(f"[ERROR] Failed to start network transport: {str(e)}")
        print("[DEBUG] Common issues:")
        print("- Port 9001 might be in use (try netstat -ano | findstr :9001)")
        print("- Missing dependencies (try pip install cryptography)")
        print("- Firewall blocking the port")
        return
    
    gossip = GossipProtocol(reliability=0.95)
    gossip.connect_to_network_transport(transport)
    
    consensus = Consensus(consensus_type="MAJORITY")
    rule_engine = RuleEngine()
    
    # Создаем агентов
    agents = {}
    for i in range(5):
        agent_id = f"agent-{i+1}"
        if i % 2 == 0:  # Чередуем типы агентов
            agents[agent_id] = LearningAgent(agent_id)
        else:
            agents[agent_id] = BaseAgent(agent_id)
        
        # Подключаем агентов к сети
        agents[agent_id].connect_to_network(gossip)
    
    print(f"Создано {len(agents)} агентов")
    
    # Объявляем присутствие агентов в сети
    for agent_id, agent in agents.items():
        agent.announce_presence()
        time.sleep(0.5)  # Пауза для имитации реальной сети
    
    print("\n--- Начало симуляции ---\n")
    
    # Симулируем обнаружение угрозы одним из агентов
    initiator_id = random.choice(list(agents.keys()))
    initiator = agents[initiator_id]
    
    print(f"\n[Симуляция] Агент {initiator_id} обнаруживает угрозу...\n")
    threat_id = simulate_threat(initiator)
    
    # Даем время на распространение информации об угрозе
    time.sleep(1)
    
    # Инициатор предлагает правило безопасности
    print(f"\n[Симуляция] Агент {initiator_id} предлагает правило безопасности...\n")
    
    if isinstance(initiator, LearningAgent):
        # Обучающийся агент предлагает правило на основе своего опыта
        rule_id = initiator.suggest_rule(threat_id)
    else:
        # Базовый агент предлагает простое правило
        rule_data = {
            "type": "BLOCK",
            "target": "192.168.1.100",  # Источник угрозы
            "action": "BLOCK",
            "duration": 3600,  # 1 час
            "description": "Блокировка подозрительного источника"
        }
        rule_id = initiator.propose_rule(rule_data, threat_id)
    
    # Даем время на распространение информации о правиле
    time.sleep(1)
    
    # Симулируем процесс голосования
    print(f"\n[Симуляция] Агенты голосуют за предложенное правило...\n")
    
    # Собираем голоса в механизм консенсуса
    for agent_id, agent in agents.items():
        if agent_id != initiator_id:  # Инициатор уже "проголосовал" предложив правило
            # В 80% случаев агенты соглашаются с правилом
            approve = random.random() < 0.8
            vote = agent.vote_for_rule(rule_id, approve)
            consensus.register_vote(rule_id, agent_id, "APPROVE" if approve else "REJECT", 
                                   agent.reputation.get(initiator_id, 50))
    
    # Даем время на распространение голосов
    time.sleep(1)
    
    # Проверяем консенсус
    print(f"\n[Симуляция] Проверка консенсуса для правила {rule_id}...\n")
    status, ratio = consensus.check_consensus(rule_id, len(agents))
    
    if status == "APPROVED":
        print(f"\n[Симуляция] Правило {rule_id} одобрено консенсусом. Применение правила...\n")
        
        # Регистрируем правило в движке правил
        rule = None
        for agent in agents.values():
            if rule_id in agent.proposed_rules:
                rule = agent.proposed_rules[rule_id]
                break
        
        if rule:
            rule_engine.register_rule(rule)
            
            # Все агенты применяют правило
            for agent_id, agent in agents.items():
                agent.apply_rule(rule_id)
                
            # Применяем правило в движке правил
            rule_engine.apply_rule(rule_id)
            
            print(f"\n[Симуляция] Правило {rule_id} успешно применено всеми агентами\n")
        else:
            print(f"\n[Симуляция] Ошибка: правило {rule_id} не найдено\n")
    else:
        print(f"\n[Симуляция] Правило {rule_id} отклонено консенсусом (соотношение: {ratio:.2f})\n")
    
    # Симулируем обнаружение новой угрозы для демонстрации обучения
    if any(isinstance(agent, LearningAgent) for agent in agents.values()):
        learning_agent_id = next(agent_id for agent_id, agent in agents.items() 
                                if isinstance(agent, LearningAgent))
        learning_agent = agents[learning_agent_id]
        
        print(f"\n[Симуляция] Обучение агента {learning_agent_id}...\n")
        
        # Собираем данные об угрозе и правиле
        threat = next((t for t in learning_agent.threat_history if t["id"] == threat_id), None)
        if threat:
            learning_data = {
                "threat": threat,
                "rule_id": rule_id,
                "consensus": status,
                "effectiveness": 0.85 if status == "APPROVED" else 0.2
            }
            
            learning_agent.learn(learning_data)
            
            # Если правило было одобрено, оцениваем его эффективность
            if status == "APPROVED":
                learning_agent.evaluate_rule(rule_id, 0.85)
                
                # Симулируем обнаружение похожей угрозы
                print(f"\n[Симуляция] Агент {learning_agent_id} обнаруживает новую угрозу...\n")
                new_threat_data = {
                    "type": "DDoS",
                    "severity": "high",
                    "source": "10.0.0.30",  # Другой источник
                    "target": "api-server",
                    "timestamp": time.time()
                }
                
                # Обнаруживаем угрозу и предлагаем правило на основе обучения
                new_threat_id = learning_agent.detect_threat(new_threat_data)
                time.sleep(0.5)
                
                print(f"\n[Симуляция] Агент {learning_agent_id} предлагает правило на основе обучения...\n")
                new_rule_id = learning_agent.suggest_rule(new_threat_id)
                
                print(f"\n[Симуляция] Новое правило {new_rule_id} предложено на основе обучения\n")
    
    print("\n--- Конец симуляции ---\n")
    if 'transport' in locals():
        transport.stop()

if __name__ == '__main__':
    main()