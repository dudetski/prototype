import json
import time

class Message:
    def __init__(self, sender_id, content, msg_type, signature=None):
        """
        Инициализирует сообщение
        
        Args:
            sender_id: Идентификатор отправителя
            content: Содержимое сообщения
            msg_type: Тип сообщения (THREAT, RULE_PROPOSAL, VOTE, etc.)
            signature: Цифровая подпись сообщения (опционально)
        """
        self.sender_id = sender_id
        self.content = content
        self.msg_type = msg_type
        self.timestamp = time.time()
        self.signature = signature
        self.message_id = f"{sender_id}-{int(self.timestamp)}"
    
    def to_string(self):
        """Преобразует сообщение в строку для подписи"""
        message_dict = {
            "sender_id": self.sender_id,
            "content": self.content,
            "msg_type": self.msg_type,
            "timestamp": self.timestamp,
            "message_id": self.message_id
        }
        return json.dumps(message_dict, sort_keys=True)
    
    def to_dict(self):
        """Преобразует сообщение в словарь"""
        return {
            "sender_id": self.sender_id,
            "content": self.content,
            "msg_type": self.msg_type,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "signature": self.signature.hex() if self.signature else None
        }
    
    @classmethod
    def from_dict(cls, data):
        """Создает сообщение из словаря"""
        message = cls(
            data["sender_id"],
            data["content"],
            data["msg_type"]
        )
        message.timestamp = data["timestamp"]
        message.message_id = data["message_id"]
        if data["signature"]:
            message.signature = bytes.fromhex(data["signature"])
        return message
