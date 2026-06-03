import time
import os
import hashlib
from typing import Dict

def find_partial_collisions() -> None:
    """
    Аналізує стійкість SHA-256 до пошуку колізій на урізаній довжині префіксу (від 5 до 15 бітів).
    Реалізує атаку "Birthday Attack" (парадокс днів народження) для оцінки експоненційного зростання часу.
    """
    print("\n" + "=" * 60)
    print(" Л3.3: ТАБЛИЦЯ ПОШУКУ ЧАСТКОВИХ КОЛІЗІЙ")
    print("=" * 60)
    print(f"| {'k (біти)':<10} | {'Середній час (мс)':<18} | {'Кількість спроб':<16} |")
    print(f"|{'-' * 12}|{'-' * 20}|{'-' * 18}|")

    # Досліджуємо складність для k старших бітів префіксу
    for k in range(5, 16):
        total_time = 0.0
        shift = 256 - k  # Зсув для виділення k найстарших бітів із 256-бітного числа
        attempts = 100   # Кількість експериментів для усереднення результатів

        for _ in range(attempts):
            seen: Dict[int, bytes] = {}
            start_time = time.perf_counter()

            while True:
                # Генерація випадкового блоку даних (nonce)
                msg = os.urandom(8)
                # Розрахунок стандартного хешу
                h = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
                # Бітовий зсув праворуч залишає лише k старших бітів
                prefix = h >> shift

                # Якщо такий префікс уже є в таблиці, і дані не дублюють самі себе — колізію знайдено
                if prefix in seen and seen[prefix] != msg:
                    break

                # Фіксація префіксу в пам'яті
                seen[prefix] = msg

            total_time += (time.perf_counter() - start_time)

        # Обчислюємо середній час виконання однієї успішної атаки у мілісекундах
        avg_time_ms = (total_time / attempts) * 1000
        print(f"| {k:<10} | {avg_time_ms:<18.4f} | {attempts:<16} |")
    print("-" * 54)