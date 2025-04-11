import random
from network.message import Message
import json

class GossipProtocol:
    def __init__(self, reliability=0.95):
        self.agents = {}  # agent_id -> agent
        self.message_cache = {}  # message_id -> message
        self.reliability = reliability

    def register_agent(self, agent):
        self.agents[agent.agent_id] = agent
        print(f"[Network] Агент {agent.agent_id} зарегистрирован в сети")

    def broadcast(self, message):
        self.message_cache[message.message_id] = message
        print(f"[Network] Широковещательная рассылка от {message.sender_id}: {message.msg_type}")
        for agent_id, agent in self.agents.items():
            if agent_id != message.sender_id:
                if random.random() < self.reliability:
                    agent.receive_message(message)
                else:
                    print(f"[Network] Ошибка при доставке сообщения от {message.sender_id} к {agent_id}")
        if hasattr(self, 'transport'):
            self.transport.broadcast_to_network(message)

    def send_message(self, message, recipient_id):
        self.message_cache[message.message_id] = message
        if recipient_id not in self.agents:
            print(f"[Network] Ошибка: агент {recipient_id} не найден")
            return False
        print(f"[Network] Отправка сообщения от {message.sender_id} к {recipient_id}: {message.msg_type}")
        if random.random() < self.reliability:
            self.agents[recipient_id].receive_message(message)
            return True
        else:
            print(f"[Network] Ошибка при доставке сообщения от {message.sender_id} к {recipient_id}")
            return False

    def get_random_peers(self, agent_id, count=3):
        peers = [pid for pid in self.agents.keys() if pid != agent_id]
        if len(peers) <= count:
            return peers
        return random.sample(peers, count)

    def gossip_sync(self, agent_id):
        if agent_id not in self.agents:
            print(f"[Network] Ошибка: агент {agent_id} не найден")
            return
        peers = self.get_random_peers(agent_id)
        if not peers:
            print(f"[Network] У агента {agent_id} нет соседей для синхронизации")
            return
        for peer_id in peers:
            request = Message(agent_id, {"type": "SYNC_REQUEST"}, "SYNC")
            request.signature = self.agents[agent_id].sign_message(
                request.to_string(), self.agents[agent_id].private_key
            )
            self.send_message(request, peer_id)
            print(f"[Network] Запрос синхронизации от {agent_id} к {peer_id}")

    def connect_to_network_transport(self, transport):
        self.transport = transport
        transport.gossip = self

    def process_remote_message(self, message):
        print(f"[Network] Получено удалённое сообщение от {message.sender_id}: {message.msg_type}")
        if message.message_id in self.message_cache:
            return
        self.message_cache[message.message_id] = message
        for agent_id, agent in self.agents.items():
            agent.receive_message(message)
