#!/usr/bin/env python3
from agents.base_agent import BaseAgent
from network.gossip_protocol import GossipProtocol
from network.message import Message
import time

def test_agent_connection():
    """Тестирует подключение агентов к сети"""
    gossip = GossipProtocol()
    
    # Создаем агентов
    agents = {}
    for i in range(3):
        agent_id = f"test-agent-{i+1}"
        agents[agent_id] = BaseAgent(agent_id)
        agents[agent_id].connect_to_network(gossip)
    
    print(f"[Test] Создано {len(agents)} тестовых агентов")
    
    # Проверяем подключение
    assert len(gossip.agents) == 3, "Неверное количество агентов в сети"
    print("[Test] Тест подключения агентов пройден")
    
    return gossip, agents

def test_agent_announcement():
    """Тестирует анонсирование агентов в сети"""
    gossip, agents = test_agent_connection()
    
    # Объявляем присутствие агентов
    for agent_id, agent in agents.items():
        agent.announce_presence()
        time.sleep(0.1)
    
    # Проверяем, знают ли агенты друг о друге
    time.sleep(0.5)  # Даем время на распространение сообщений
    
    for agent_id, agent in agents.items():
        # Агент должен знать всех других агентов
        expected_known = len(agents) - 1
        actual_known = len(agent.known_agents)
        
        assert actual_known == expected_known, \
            f"Агент {agent_id} знает {actual_known} агентов вместо {expected_known}"
    
    print("[Test] Тест анонсирования агентов пройден")
    
    return gossip, agents

def test_message_broadcast():
    """Тестирует рассылку сообщений"""
    gossip, agents = test_agent_announcement()
    
    # Выбираем одного агента для отправки сообщения
    sender_id = list(agents.keys())[0]
    sender = agents[sender_id]
    
    # Создаем тестовое сообщение
    test_content = {"test": "data", "value": 123}
    message = sender.create_message(test_content, "TEST_MESSAGE")
    
    # Отправляем сообщение
    gossip.broadcast(message)
    
    # Проверяем получение сообщения другими агентами
    time.sleep(0.5)  # Даем время на доставку
    
    for agent_id, agent in agents.items():
        if agent_id != sender_id:
            # Ищем сообщение в истории
            received = False
            for msg in agent.message_history:
                if (msg.msg_type == "TEST_MESSAGE" and 
                    msg.sender_id == sender_id and 
                    msg.content == test_content):
                    received = True
                    break
            
            assert received, f"Агент {agent_id} не получил тестовое сообщение"
    
    print("[Test] Тест рассылки сообщений пройден")

def test_gossip_protocol():
    """Тестирует работу gossip протокола"""
    print("\n----- Начало тестирования сетевого модуля -----\n")
    
    test_agent_connection()
    test_agent_announcement()
    test_message_broadcast()
    
    print("\n----- Тестирование сетевого модуля успешно завершено -----\n")

if __name__ == '__main__':
    test_gossip_protocol()
