class Consensus:
    def __init__(self, consensus_type="MAJORITY"):
        """
        Инициализирует механизм консенсуса
        
        Args:
            consensus_type: Тип консенсуса (MAJORITY, UNANIMOUS, WEIGHTED)
        """
        self.consensus_type = consensus_type
        self.votes = {}  # rule_id -> {agent_id: vote}
        self.rule_status = {}  # rule_id -> status
    
    def register_vote(self, rule_id, agent_id, vote, reputation=None):
        """Регистрирует голос агента"""
        if rule_id not in self.votes:
            self.votes[rule_id] = {}
            self.rule_status[rule_id] = "VOTING"
        
        self.votes[rule_id][agent_id] = {
            "vote": vote,
            "reputation": reputation if reputation is not None else 50
        }
        
        print(f"[Consensus] Зарегистрирован голос от {agent_id} за правило {rule_id}: {vote}")
    
    def check_consensus(self, rule_id, total_agents):
        """Проверяет, достигнут ли консенсус"""
        if rule_id not in self.votes:
            return "PENDING", 0.0
        
        votes = self.votes[rule_id]
        
        # Если голосовали все агенты или прошло время ожидания
        if len(votes) >= total_agents * 0.67:  # 2/3 агентов
            # Подсчитываем голоса
            if self.consensus_type == "MAJORITY":
                return self._check_majority_consensus(rule_id, votes)
            elif self.consensus_type == "UNANIMOUS":
                return self._check_unanimous_consensus(rule_id, votes)
            elif self.consensus_type == "WEIGHTED":
                return self._check_weighted_consensus(rule_id, votes)
        
        return "VOTING", len(votes) / total_agents
    
    def _check_majority_consensus(self, rule_id, votes):
        """Проверяет консенсус по большинству голосов"""
        approve_count = sum(1 for v in votes.values() if v["vote"] == "APPROVE")
        
        consensus_ratio = approve_count / len(votes)
        
        if consensus_ratio > 0.5:
            status = "APPROVED"
        else:
            status = "REJECTED"
        
        self.rule_status[rule_id] = status
        print(f"[Consensus] Правило {rule_id} {status.lower()} большинством голосов ({approve_count}/{len(votes)})")
        
        return status, consensus_ratio
    
    def _check_unanimous_consensus(self, rule_id, votes):
        """Проверяет единогласный консенсус"""
        approve_count = sum(1 for v in votes.values() if v["vote"] == "APPROVE")
        
        consensus_ratio = approve_count / len(votes)
        
        if consensus_ratio == 1.0:
            status = "APPROVED"
        else:
            status = "REJECTED"
        
        self.rule_status[rule_id] = status
        print(f"[Consensus] Правило {rule_id} {status.lower()} {'единогласно' if status == 'APPROVED' else ''} ({approve_count}/{len(votes)})")
        
        return status, consensus_ratio
    
    def _check_weighted_consensus(self, rule_id, votes):
        """Проверяет консенсус с учетом репутации агентов"""
        total_weight = sum(v["reputation"] for v in votes.values())
        approve_weight = sum(v["reputation"] for v in votes.values() if v["vote"] == "APPROVE")
        
        consensus_ratio = approve_weight / total_weight if total_weight > 0 else 0
        
        if consensus_ratio > 0.5:
            status = "APPROVED"
        else:
            status = "REJECTED"
        
        self.rule_status[rule_id] = status
        print(f"[Consensus] Правило {rule_id} {status.lower()} с взвешенным консенсусом ({approve_weight}/{total_weight})")
        
        return status, consensus_ratio
    
    def get_rule_status(self, rule_id):
        """Возвращает статус правила"""
        return self.rule_status.get(rule_id, "UNKNOWN")
