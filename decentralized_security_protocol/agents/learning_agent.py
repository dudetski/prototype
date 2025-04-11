from agents.base_agent import BaseAgent
import numpy as np
import logging
import time
from datetime import datetime
import random

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
        self.threat_patterns = {}  # тип угрозы -> паттерны
        self.rule_effectiveness = {}  # rule_id -> оценка эффективности
        self.threat_counters = {}  # host_id -> {threat_type -> count}
        
        # Параметры обучения
        self.learning_rate = 0.1
        self.similarity_threshold = 0.7
        self.min_confidence = 0.6
        
        # Коэффициенты важности признаков
        self.feature_weights = {
            "source": 0.3,
            "target": 0.2,
            "type": 0.35,
            "protocol": 0.15
        }
        
        # История обучения
        self.learning_history = []
        
        self.logger.info(f"Инициализирован обучающийся агент {agent_id}")
    
    def learn(self, data):
        """Обучается на новых данных"""
        timestamp = self.get_timestamp()
        formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Добавляем метаданные
        learning_event = {
            "data": data,
            "timestamp": timestamp,
            "formatted_time": formatted_time
        }
        
        self.logger.info(f"Обучение на новых данных...")
        self.training_data.append(learning_event)
        
        # Извлечение паттернов угроз
        if "threat" in data:
            threat_type = data["threat"].get("type", "unknown")
            threat_data = data["threat"].get("data", {})
            
            if threat_type not in self.threat_patterns:
                self.threat_patterns[threat_type] = []
            
            # Добавляем новый паттерн только если он отличается от существующих
            is_new_pattern = True
            for pattern in self.threat_patterns[threat_type]:
                if self._calculate_similarity(threat_data, pattern) > 0.9:
                    is_new_pattern = False
                    break
            
            if is_new_pattern:
                self.threat_patterns[threat_type].append(threat_data)
                self.logger.info(f"Изучен новый паттерн для угрозы типа {threat_type}")
                
                # Обновляем счетчики угроз
                source = threat_data.get("source")
                if source:
                    if source not in self.threat_counters:
                        self.threat_counters[source] = {}
                    if threat_type not in self.threat_counters[source]:
                        self.threat_counters[source][threat_type] = 0
                    self.threat_counters[source][threat_type] += 1
        
        # Обновление весов признаков на основе новых данных
        self._update_feature_weights(data)
        
        return learning_event
    
    def _update_feature_weights(self, data):
        """Обновляет веса признаков на основе новых данных"""
        if "threat" in data and "rule" in data and "effectiveness" in data:
            effectiveness = data["effectiveness"]
            features_present = set()
            
            # Определяем, какие признаки присутствуют в данных
            threat_data = data["threat"].get("data", {})
            for feature in self.feature_weights:
                if feature in threat_data:
                    features_present.add(feature)
            
            # Корректируем веса на основе эффективности правила
            adjustment = (effectiveness - 0.5) * self.learning_rate
            for feature in features_present:
                self.feature_weights[feature] += adjustment
            
            # Нормализуем веса
            total_weight = sum(self.feature_weights.values())
            for feature in self.feature_weights:
                self.feature_weights[feature] /= total_weight
    
    def evaluate_rule(self, rule_id, effectiveness, update_model=True):
        """
        Оценивает эффективность правила и обновляет модель
        
        Args:
            rule_id: Идентификатор правила
            effectiveness: Значение эффективности (0.0 - 1.0)
            update_model: Флаг обновления модели
        """
        old_effectiveness = self.rule_effectiveness.get(rule_id, 0.5)
        self.rule_effectiveness[rule_id] = effectiveness
        
        self.logger.info(f"Оценка эффективности правила {rule_id}: {effectiveness:.2f} (было: {old_effectiveness:.2f})")
        
        # Получаем правило и связанную с ним угрозу
        rule = None
        for r in self.rules + list(self.proposed_rules.values()):
            if r.get("id") == rule_id:
                rule = r
                break
        
        if rule and update_model:
            # Находим связанную угрозу
            threat_id = rule.get("threat_id")
            threat = None
            if threat_id:
                for t in self.threat_history:
                    if t.get("id") == threat_id:
                        threat = t
                        break
            
            if threat:
                # Обучаемся на основе этой пары (угроза, правило, эффективность)
                self.learn({
                    "threat": threat,
                    "rule": rule,
                    "effectiveness": effectiveness
                })
                
                # Если правило неэффективно, предлагаем новое
                if effectiveness < 0.3 and rule["status"] == "APPROVED":
                    self.logger.warning(f"Правило {rule_id} неэффективно. Предлагаем новое...")
                    return self.suggest_rule(threat_id)
        
        return rule_id
    
    def detect_threat_with_learning(self, data):
        """
        Обнаруживает угрозу с использованием обученных паттернов
        
        Args:
            data: Данные для анализа на наличие угрозы
        
        Returns:
            str or None: Идентификатор обнаруженной угрозы или None
        """
        detected_threats = []
        
        # Проходим по всем типам угроз и их паттернам
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                similarity = self._calculate_similarity(data, pattern)
                if similarity > self.similarity_threshold:
                    # Рассчитываем уверенность на основе количества подобных угроз
                    source = data.get("source", "unknown")
                    confidence_boost = 0
                    
                    if source in self.threat_counters and threat_type in self.threat_counters[source]:
                        # Если от этого источника уже были подобные угрозы, повышаем уверенность
                        threat_count = self.threat_counters[source][threat_type]
                        confidence_boost = min(0.3, threat_count * 0.05)  # Максимум +0.3 к уверенности
                    
                    detected_threats.append({
                        "type": threat_type,
                        "confidence": similarity + confidence_boost,
                        "data": data,
                        "pattern_match": pattern
                    })
        
        if detected_threats:
            # Берем угрозу с наивысшей уверенностью
            best_threat = max(detected_threats, key=lambda x: x["confidence"])
            
            if best_threat["confidence"] >= self.min_confidence:
                self.logger.warning(f"Обнаружена угроза с использованием обучения: {best_threat['type']} "
                                   f"(уверенность: {best_threat['confidence']:.2f})")
                
                # Обогащаем данные угрозы дополнительной информацией
                threat_data = best_threat.copy()
                threat_data["detected_by_learning"] = True
                threat_data["confidence_score"] = best_threat["confidence"]
                threat_data["matching_pattern"] = best_threat["pattern_match"]
                
                # Удаляем служебные поля перед отправкой
                if "pattern_match" in threat_data:
                    del threat_data["pattern_match"]
                
                return self.detect_threat(threat_data)
        
        return None
    
    def suggest_rule(self, threat_id):
        """
        Предлагает правило на основе обученных данных
        
        Args:
            threat_id: Идентификатор угрозы
        
        Returns:
            str or None: Идентификатор предложенного правила или None
        """
        # Ищем угрозу в истории
        threat = None
        for t in self.threat_history:
            if t.get("id") == threat_id:
                threat = t
                break
        
        if not threat:
            self.logger.error(f"Ошибка: угроза {threat_id} не найдена")
            return None
        
        threat_type = threat.get("data", {}).get("type", "unknown")
        source = threat.get("data", {}).get("source", "unknown")
        
        # Ищем правила для подобных угроз
        similar_rules = []
        
        for rule_id, rule in self.proposed_rules.items():
            if rule.get("threat_id") and rule.get("status") == "APPROVED":
                for t in self.threat_history:
                    if t.get("id") == rule["threat_id"] and t.get("data", {}).get("type") == threat_type:
                        effectiveness = self.rule_effectiveness.get(rule_id, 0.5)
                        similar_rules.append((rule, effectiveness))
        
        # Также проверяем применённые правила
        for rule in self.rules:
            if rule.get("threat_id"):
                for t in self.threat_history:
                    if t.get("id") == rule["threat_id"] and t.get("data", {}).get("type") == threat_type:
                        effectiveness = self.rule_effectiveness.get(rule["id"], 0.7)  # Для применённых правил выше базовая эффективность
                        similar_rules.append((rule, effectiveness))
        
        # Определяем действие и длительность на основе прошлого опыта
        action = "ALERT"
        duration = 1800  # 30 минут по умолчанию
        
        # Если это повторная угроза от того же источника, ужесточаем меры
        repeat_threat = False
        threat_count = 0
        
        if source in self.threat_counters and threat_type in self.threat_counters[source]:
            threat_count = self.threat_counters[source][threat_type]
            if threat_count > 1:
                repeat_threat = True
        
        if repeat_threat:
            # Повторная угроза - усиливаем меры
            if threat_count > 5:
                action = "ISOLATE"
                duration = 86400  # 24 часа для злостных нарушителей
            elif threat_count > 2:
                action = "BLOCK"
                duration = 3600 * 6  # 6 часов
            else:
                action = "BLOCK"
                duration = 3600  # 1 час
        
        if similar_rules:
            # Выбираем правило с наивысшей эффективностью
            best_rule, effectiveness = max(similar_rules, key=lambda x: x[1])
            
            # Если найдено эффективное правило, используем его как шаблон
            if effectiveness > 0.7:
                self.logger.info(f"Предлагается правило на основе эффективного правила {best_rule['id']} "
                                f"(эффективность: {effectiveness:.2f})")
                
                # Базируем новое правило на лучшем
                action = best_rule["data"].get("action", action)
                
                # Если это повторная угроза, увеличиваем длительность
                original_duration = best_rule["data"].get("duration", 1800)
                if repeat_threat:
                    duration = min(original_duration * 2, 86400)  # Не более 24 часов
                else:
                    duration = original_duration
        
        # Создаем новое правило
        rule_data = {
            "type": "SECURITY",
            "target": source,
            "action": action,
            "duration": duration,
            "description": f"Правило для защиты от {threat_type} (предложено обученным агентом)",
            "created_by_learning": True,
            "threat_type": threat_type,
            "confidence": 0.8 if repeat_threat else 0.6
        }
        
        self.logger.info(f"Предлагается новое правило: {rule_data}")
        return self.propose_rule(rule_data, threat_id)
    
    def _calculate_similarity(self, data1, data2):
        """
        Рассчитывает сходство между двумя наборами данных
        
        Args:
            data1: Первый набор данных
            data2: Второй набор данных
        
        Returns:
            float: Оценка сходства (0.0 - 1.0)
        """
        if not isinstance(data1, dict) or not isinstance(data2, dict):
            return 0.0
        
        # Находим общие ключи
        common_keys = set(data1.keys()) & set(data2.keys())
        if not common_keys:
            return 0.0
        
        total_weight = 0
        weighted_similarity = 0
        
        for key in common_keys:
            # Определяем вес ключа
            weight = self.feature_weights.get(key, 0.1)
            total_weight += weight
            
            # Сравниваем значения
            if data1[key] == data2[key]:
                weighted_similarity += weight
            elif isinstance(data1[key], str) and isinstance(data2[key], str):
                # Для строк учитываем частичное совпадение
                str_similarity = self._string_similarity(data1[key], data2[key])
                weighted_similarity += weight * str_similarity
        
        # Нормализация, если есть веса
        if total_weight > 0:
            return weighted_similarity / total_weight
        return 0.0
    
    def _string_similarity(self, str1, str2):
        """Рассчитывает сходство между двумя строками"""
        if str1 == str2:
            return 1.0
        
        # Простой алгоритм для демонстрации
        # Для реального проекта можно использовать расстояние Левенштейна или другие метрики
        shorter = min(str1, str2, key=len)
        longer = max(str1, str2, key=len)
        
        if not shorter:
            return 0.0
        
        # Проверяем вхождение
        if shorter in longer:
            return len(shorter) / len(longer)
        
        # Подсчитываем общие символы
        common_chars = sum(1 for c in shorter if c in longer)
        return common_chars / len(shorter)
    
    def analyze_host_behavior(self, host_id, time_period=86400):
        """
        Анализирует поведение хоста за указанный период времени
        
        Args:
            host_id: Идентификатор хоста
            time_period: Период времени в секундах (по умолчанию 24 часа)
        
        Returns:
            dict: Результаты анализа
        """
        if host_id not in self.host_events:
            self.logger.warning(f"Нет данных о поведении хоста {host_id}")
            return None
        
        current_time = self.get_timestamp()
        events = [e for e in self.host_events[host_id] 
                 if current_time - e["timestamp"] <= time_period]
        
        if not events:
            self.logger.warning(f"Нет событий хоста {host_id} за указанный период")
            return None
        
        # Анализируем события
        event_types = {}
        connections = {}
        protocols = {}
        hourly_activity = [0] * 24
        
        for event in events:
            # Счетчик типов событий
            event_type = event["type"]
            if event_type not in event_types:
                event_types[event_type] = 0
            event_types[event_type] += 1
            
            # Анализируем соединения
            if "data" in event and "source" in event["data"] and "target" in event["data"]:
                source = event["data"]["source"]
                target = event["data"]["target"]
                connection = f"{source}->{target}"
                
                if connection not in connections:
                    connections[connection] = 0
                connections[connection] += 1
            
            # Анализируем протоколы
            if "data" in event and "protocol" in event["data"]:
                protocol = event["data"]["protocol"]
                if protocol not in protocols:
                    protocols[protocol] = 0
                protocols[protocol] += 1
            
            # Активность по часам
            event_time = datetime.fromtimestamp(event["timestamp"])
            hour = event_time.hour
            hourly_activity[hour] += 1
        
        # Рассчитываем риск на основе истории угроз
        risk_score = 0
        threat_events = sum(1 for e in events if e["type"] in ["threat", "threat_reported"])
        if events:
            threat_ratio = threat_events / len(events)
            risk_score = threat_ratio * 100
        
        analysis = {
            "host_id": host_id,
            "analyzed_events": len(events),
            "time_period": time_period,
            "event_types": event_types,
            "connections": connections,
            "protocols": protocols,
            "hourly_activity": hourly_activity,
            "risk_score": risk_score,
            "analysis_timestamp": current_time
        }
        
        self.logger.info(f"Проведен анализ поведения хоста {host_id}. Оценка риска: {risk_score:.2f}")
        return analysis
    
    def optimize_rules(self):
        """
        Оптимизирует существующие правила на основе накопленных данных об их эффективности
        
        Returns:
            list: Список оптимизированных правил
        """
        optimized_rules = []
        
        # Анализируем эффективность существующих правил
        for rule in self.rules + list(self.proposed_rules.values()):
            rule_id = rule.get("id")
            if not rule_id:
                continue
                
            effectiveness = self.rule_effectiveness.get(rule_id, 0.5)
            
            # Для правил с низкой эффективностью
            if effectiveness < 0.4 and rule.get("status") == "APPROVED":
                # Предлагаем улучшенную версию
                improved_rule = self._improve_rule(rule)
                if improved_rule:
                    self.logger.info(f"Оптимизировано правило {rule_id} (эффективность: {effectiveness:.2f})")
                    optimized_rules.append(improved_rule)
        
        return optimized_rules
    
    def _improve_rule(self, original_rule):
        """
        Улучшает существующее правило
        
        Args:
            original_rule: Исходное правило
        
        Returns:
            str or None: Идентификатор нового правила или None
        """
        rule_data = original_rule.get("data", {}).copy()
        
        # Увеличиваем строгость правила
        if rule_data.get("action") == "ALERT":
            rule_data["action"] = "BLOCK"
        elif rule_data.get("action") == "BLOCK":
            rule_data["action"] = "ISOLATE"
        
        # Увеличиваем длительность для повышения безопасности
        if "duration" in rule_data:
            rule_data["duration"] = min(rule_data["duration"] * 2, 86400)  # не более 24 часов
        
        # Добавляем описание для отслеживания
        rule_data["description"] = f"Оптимизированная версия правила {original_rule['id']} " + \
                                  rule_data.get("description", "")
        rule_data["optimized_from"] = original_rule["id"]
        
        # Предлагаем новое правило
        return self.propose_rule(rule_data, original_rule.get("threat_id"))
    
    def receive_message(self, message):
        """
        Переопределяем метод получения сообщений для добавления обучения
        
        Args:
            message: Полученное сообщение
        
        Returns:
            bool: Результат обработки сообщения
        """
        # Вызываем метод базового класса
        result = super().receive_message(message)
        
        # Дополнительная обработка для обучения
        if result and message.msg_type in ["THREAT", "RULE_PROPOSAL", "ANOMALY_DETECTED"]:
            # Обучаемся на полученных данных
            learning_data = {
                "message_type": message.msg_type,
                "content": message.content,
                "sender": message.sender_id
            }
            self.learn(learning_data)
            
            # Для сообщений о правилах проверяем, можем ли мы их улучшить
            if message.msg_type == "RULE_PROPOSAL" and random.random() < 0.3:  # 30% вероятность
                rule = message.content
                if "data" in rule:
                    improved_data = self._suggest_improvements(rule["data"])
                    if improved_data != rule["data"]:
                        self.logger.info(f"Предлагаю улучшение для правила {rule.get('id', 'неизвестно')}")
        
        return result
    
    def _suggest_improvements(self, rule_data):
        """
        Предлагает улучшения для правила
        
        Args:
            rule_data: Данные правила
        
        Returns:
            dict: Улучшенные данные правила
        """
        improved_data = rule_data.copy()
        
        # Проверяем тип угрозы
        if "threat_type" in improved_data:
            threat_type = improved_data["threat_type"]
            
            # Если у нас есть опыт с этим типом угроз
            if threat_type in self.threat_patterns and len(self.threat_patterns[threat_type]) > 2:
                # Если это опасная угроза, усиливаем правило
                if threat_type in ["DDoS", "RCE", "SQLi", "XSS"]:
                    if improved_data.get("action") == "ALERT":
                        improved_data["action"] = "BLOCK"
                    
                    # Увеличиваем длительность для опасных угроз
                    if "duration" in improved_data:
                        improved_data["duration"] = min(improved_data["duration"] * 1.5, 86400)
        
        return improved_data
