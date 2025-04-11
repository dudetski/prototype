# network/transport.py
import socket
import threading
import json
import pickle
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from decentralized_security_protocol.network.message import Message

class NetworkTransport:
    def __init__(self, host='0.0.0.0', port=9000):
        self.host = host
        self.port = port
        self.gossip = None
        self.known_nodes = {}  # ip:port -> node_id
        self.server_socket = None
        self.running = False
    
    def start_server(self):
        """Запускает сервер для приёма сообщений"""
        print(f"[TRANSPORT] Starting server on {self.host}:{self.port}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True
        
        # Запускаем поток для обработки входящих соединений
        server_thread = threading.Thread(target=self._handle_connections)
        server_thread.daemon = True
        server_thread.start()
        
        print(f"[Network] Сервер запущен на {self.host}:{self.port}")
    
    def _handle_connections(self):
        """Обрабатывает входящие соединения"""
        while self.running:
            try:
                client_sock, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client, 
                    args=(client_sock, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[Network] Ошибка приёма соединения: {e}")
    
    def _handle_client(self, client_sock, address):
        """Обрабатывает сообщения от клиента"""
        try:
            # Получаем данные
            data = b""
            while True:
                chunk = client_sock.recv(4096)
                data += chunk
                if len(chunk) < 4096:
                    break
            
            # Десериализуем сообщение
            if data:
                message_dict = pickle.loads(data)
                message = Message.from_dict(message_dict)
                
                # Передаём сообщение в протокол gossip
                if self.gossip:
                    self.gossip.process_remote_message(message)
                    
                # Отправляем подтверждение
                client_sock.sendall(b"ACK")
        except Exception as e:
            print(f"[Network] Ошибка обработки клиента: {e}")
        finally:
            client_sock.close()
    
    def send_message(self, message, node_address):
        """Отправляет сообщение на удалённый узел"""
        host, port = node_address
        try:
            # Сериализуем сообщение
            message_data = pickle.dumps(message.to_dict())
            
            # Создаём соединение и отправляем
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            client_socket.sendall(message_data)
            
            # Ждём подтверждения
            response = client_socket.recv(1024)
            client_socket.close()
            
            return response == b"ACK"
        except Exception as e:
            print(f"[Network] Ошибка отправки сообщения на {host}:{port}: {e}")
            return False
    
    def register_node(self, node_id, host, port):
        """Регистрирует удалённый узел"""
        self.known_nodes[(host, port)] = node_id
        print(f"[Network] Зарегистрирован узел {node_id} на {host}:{port}")
    
    def broadcast_to_network(self, message):
        """Рассылает сообщение всем известным узлам"""
        for node_address, node_id in self.known_nodes.items():
            self.send_message(message, node_address)
    
    def stop(self):
        """Останавливает сервер"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
