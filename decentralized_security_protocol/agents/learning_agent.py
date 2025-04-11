from agents.base_agent import BaseAgent

class LearningAgent(BaseAgent):
    def __init__(self, agent_id):
        """
        Инициализирует обучающегося агента
        
        Args:
            agent_id: Уникальный идентификатор агента
        """
        super().__init__(agent_id)
        
        # Данные для обучения
        self.training_data = []
        self.threat_patterns = {}  # тип угрозы -> паттерн
        self.rule_effectiveness = {}  # rule_id -> оценка эффективности
    
    def learn(self, data):
        """Обучается на новых данных"""
        print(f"[{self.agent_id}] Обучение на новых данных...")
        self.training_data.append(data)
        
        # Простой механизм обучения - извлечение паттернов угроз
        if "threat" in data:
            threat_type = data["threat"].get("type", "unknown")
            threat_data = data["threat"].get("data", {})
            
            if threat_type not in self.threat_patterns:
                self.threat_patterns[threat_type] = []
            
            self.threat_patterns[threat_type].append(threat_data)
            print(f"[{self.agent_id}] Изучен новый паттерн для угрозы типа {threat_type}")
    
    def evaluate_rule(self, rule_id, effectiveness):
        """Оценивает эффективность правила"""
        print(f"[{self.agent_id}] Оценка эффективности правила {rule_id}: {effectiveness}")
        self.rule_effectiveness[rule_id] = effectiveness
    
    def detect_threat_with_learning(self, data):
        """Обнаруживает угрозу с использованием обученных паттернов"""
        # Простая эвристика для демонстрации
        detected_threats = []
        
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                # Очень упрощенное сравнение, в реальной системе здесь
                # должен быть более сложный алгоритм
                similarity = self._calculate_similarity(data, pattern)
                if similarity > 0.7:  # пороговое значение
                    detected_threats.append({
                        "type": threat_type,
                        "confidence": similarity,
                        "data": data
                    })
        
        if detected_threats:
            # Берем угрозу с наивысшей уверенностью
            best_threat = max(detected_threats, key=lambda x: x["confidence"])
            print(f"[{self.agent_id}] Обнаружена угроза с использованием обучения: {best_threat}")
            return self.detect_threat(best_threat)
        
        return None
    
    def suggest_rule(self, threat_id):
        """Предлагает правило на основе обученных данных"""
        # Ищем угрозу в истории
        threat = None
        for t in self.threat_history:
            if t["id"] == threat_id:
                threat = t
                break
        
        if not threat:
            print(f"[{self.agent_id}] Ошибка: угроза {threat_id} не найдена")
            return None
        
        # Ищем правила для подобных угроз
        similar_rules = []
        threat_type = threat.get("data", {}).get("type", "unknown")
        
        for rule_id, rule in self.proposed_rules.items():
            if rule.get("threat_id") and rule.get("status") == "APPROVED":
                for t in self.threat_history:
                    if t["id"] == rule["threat_id"] and t.get("data", {}).get("type") == threat_type:
                        effectiveness = self.rule_effectiveness.get(rule_id, 0.5)
                        similar_rules.append((rule, effectiveness))
        
        if similar_rules:
            # Выбираем правило с наивысшей эффективностью
            best_rule = max(similar_rules, key=lambda x: x[1])
            print(f"[{self.agent_id}] Предлагается правило на основе обучения: {best_rule[0]['data']}")
            
            # Создаем новое правило на основе лучшего
            rule_data = {
                "type": "BLOCK",
                "target": threat.get("data", {}).get("source", "unknown"),
                "action": "ISOLATE",
                "duration": 3600,  # 1 час
                "based_on_rule": best_rule[0]["id"]
            }
            
            return self.propose_rule(rule_data, threat_id)
        else:
            # Создаем новое базовое правило
            rule_data = {
                "type": "BLOCK",
                "target": threat.get("data", {}).get("source", "unknown"),
                "action": "ALERT",
                "duration": 1800  # 30 минут
            }
            
            return self.propose_rule(rule_data, threat_id)
    
    def _calculate_similarity(self, data1, data2):
        """Простой расчет сходства между двумя наборами данных"""
        # Это очень упрощенная реализация
        # В реальной системе здесь может быть более сложный алгоритм
        
        if not isinstance(data1, dict) or not isinstance(data2, dict):
            return 0.0
        
        # Считаем количество совпадающих ключей и значений
        matching_keys = set(data1.keys()) & set(data2.keys())
        if not matching_keys:
            return 0.0
        
        matches = 0
        for key in matching_keys:
            if data1[key] == data2[key]:
                matches += 1
        
        return matches / len(matching_keys)
