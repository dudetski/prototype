import time
import statistics
from collections import defaultdict

class BehaviorProfiler:
    """
    Класс для профилирования поведения хоста и обнаружения аномалий
    """
    def __init__(self, learning_period=3600):  # период обучения по умолчанию 1 час
        self.learning_period = learning_period
        self.learning_start_time = None
        self.is_learning = False
        self.is_trained = False
        
        # Хранилище данных о поведении
        self.behavior_data = defaultdict(list)
        
        # Нормальные профили поведения (после обучения)
        self.normal_profiles = {}
        
        # Пороговые значения для разных метрик
        self.thresholds = {}
        
        # Очищенные данные для определения нормы
        self.filtered_data = {}
    
    def start_learning(self):
        """Запускает период обучения"""
        self.learning_start_time = time.time()
        self.is_learning = True
        self.is_trained = False
        print("[BehaviorProfiler] Запущен период обучения нормального поведения")
    
    def add_observation(self, category, data):
        """
        Добавляет наблюдение поведения
        
        Args:
            category: Категория поведения (например, 'network_traffic', 'cpu_usage')
            data: Данные наблюдения
        """
        self.behavior_data[category].append({
            "timestamp": time.time(),
            "value": data
        })
        
        # Проверяем, не закончился ли период обучения
        if self.is_learning and time.time() - self.learning_start_time > self.learning_period:
            self.finalize_learning()
    
    def finalize_learning(self):
        """Завершает обучение и создает профили нормального поведения"""
        if not self.is_learning:
            return
            
        print("[BehaviorProfiler] Завершение периода обучения, анализ данных...")
        self.is_learning = False
        
        # Для каждой категории поведения вычисляем статистические показатели
        for category, observations in self.behavior_data.items():
            if not observations:
                continue
                
            values = [obs["value"] for obs in observations if isinstance(obs["value"], (int, float))]
            
            if not values:
                continue
                
            # Отфильтровываем выбросы (простой метод с использованием стандартного отклонения)
            mean = statistics.mean(values)
            stdev = statistics.stdev(values) if len(values) > 1 else 0
            
            # Данные в пределах 2 стандартных отклонений считаем нормальными
            filtered_values = [v for v in values if abs(v - mean) <= 2 * stdev]
            
            if filtered_values:
                filtered_mean = statistics.mean(filtered_values)
                filtered_stdev = statistics.stdev(filtered_values) if len(filtered_values) > 1 else 0
                
                self.normal_profiles[category] = {
                    "mean": filtered_mean,
                    "stdev": filtered_stdev,
                    "min": min(filtered_values),
                    "max": max(filtered_values),
                    "sample_size": len(filtered_values)
                }
                
                # Устанавливаем пороговое значение как 3 стандартных отклонения
                self.thresholds[category] = filtered_stdev * 3
                
                self.filtered_data[category] = filtered_values
        
        self.is_trained = True
        print(f"[BehaviorProfiler] Обучение завершено, создано {len(self.normal_profiles)} профилей поведения")
    
    def check_anomaly(self, category, value):
        """
        Проверяет, является ли наблюдение аномальным
        
        Args:
            category: Категория поведения
            value: Значение для проверки
            
        Returns:
            tuple: (is_anomaly, confidence, details)
        """
        if not self.is_trained or category not in self.normal_profiles:
            return False, 0, "Профиль не обучен"
        
        profile = self.normal_profiles[category]
        threshold = self.thresholds[category]
        
        # Вычисляем, насколько значение отклоняется от нормы
        deviation = abs(value - profile["mean"])
        
        # Определяем, является ли отклонение аномальным
        is_anomaly = deviation > threshold
        
        # Вычисляем уверенность (чем больше отклонение, тем выше уверенность)
        if threshold > 0:
            confidence = min(1.0, deviation / threshold) if is_anomaly else 0.0
        else:
            confidence = 1.0 if is_anomaly else 0.0
        
        details = {
            "value": value,
            "normal_mean": profile["mean"],
            "deviation": deviation,
            "threshold": threshold,
            "is_anomaly": is_anomaly,
            "confidence": confidence
        }
        
        return is_anomaly, confidence, details
    
    def get_training_status(self):
        """Возвращает статус обучения"""
        if self.is_trained:
            return "trained", 1.0
        elif self.is_learning:
            elapsed = time.time() - self.learning_start_time
            progress = min(1.0, elapsed / self.learning_period)
            return "learning", progress
        else:
            return "untrained", 0.0