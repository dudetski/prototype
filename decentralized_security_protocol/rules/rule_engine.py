class RuleEngine:
    def __init__(self):
        """Инициализирует движок правил"""
        self.rules = {}  # rule_id -> rule
        self.active_rules = {}  # rule_id -> expiration_time
        self.rule_actions = {
            "ALERT": self._execute_alert,
            "BLOCK": self._execute_block,
            "ISOLATE": self._execute_isolate,
            "SCAN": self._execute_scan
        }
    
    def register_rule(self, rule):
        """Регистрирует правило в движке"""
        rule_id = rule["id"]
        self.rules[rule_id] = rule
        print(f"[RuleEngine] Зарегистрировано правило: {rule_id}")
        return rule_id
    
    def apply_rule(self, rule_id, target=None):
        """Применяет правило"""
        if rule_id not in self.rules:
            print(f"[RuleEngine] Ошибка: правило {rule_id} не найдено")
            return False
        
        rule = self.rules[rule_id]
        
        if rule.get("status") != "APPROVED":
            print(f"[RuleEngine] Ошибка: правило {rule_id} не одобрено")
            return False
        
        # Если цель не указана, используем цель из правила
        if target is None:
            target = rule["data"].get("target")
        
        # Получаем тип действия
        action_type = rule["data"].get("action", "ALERT")
        
        # Выполняем действие
        if action_type in self.rule_actions:
            result = self.rule_actions[action_type](rule, target)
            if result:
                # Устанавливаем срок действия правила
                import time
                duration = rule["data"].get("duration", 3600)  # по умолчанию 1 час
                self.active_rules[rule_id] = time.time() + duration
                print(f"[RuleEngine] Правило {rule_id} применено к {target} на {duration} секунд")
            return result
        else:
            print(f"[RuleEngine] Ошибка: неизвестный тип действия {action_type}")
            return False
    
    def check_rule_applicability(self, event, target):
        """Проверяет, применимы ли активные правила к событию"""
        applicable_rules = []
        
        # Удаляем устаревшие правила
        self._cleanup_expired_rules()
        
        # Проверяем все активные правила
        for rule_id in self.active_rules:
            rule = self.rules[rule_id]
            
            # Простая проверка на совпадение цели
            if rule["data"].get("target") == target:
                applicable_rules.append(rule)
        
        return applicable_rules
    
    def _cleanup_expired_rules(self):
        """Удаляет устаревшие правила"""
        import time
        current_time = time.time()
        
        expired = [rule_id for rule_id, expiration in self.active_rules.items() 
                  if expiration < current_time]
        
        for rule_id in expired:
            del self.active_rules[rule_id]
            print(f"[RuleEngine] Правило {rule_id} истекло и удалено из активных")
    
    def _execute_alert(self, rule, target):
        """Выполняет действие ALERT"""
        print(f"[RuleEngine] ALERT: {rule['data'].get('description', 'Обнаружена угроза')} на {target}")
        return True
    
    def _execute_block(self, rule, target):
        """Выполняет действие BLOCK"""
        print(f"[RuleEngine] BLOCK: Заблокирован {target}")
        return True
    
    def _execute_isolate(self, rule, target):
        """Выполняет действие ISOLATE"""
        print(f"[RuleEngine] ISOLATE: Изолирован {target}")
        return True
    
    def _execute_scan(self, rule, target):
        """Выполняет действие SCAN"""
        print(f"[RuleEngine] SCAN: Сканирование {target}")
        return True