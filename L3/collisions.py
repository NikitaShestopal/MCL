import time
import os
import hashlib
from typing import Dict

def find_partial_collisions() -> None:
    print("\n" + "=" * 60)
    print(" Л3.3: ТАБЛИЦЯ ПОШУКУ ЧАСТКОВИХ КОЛІЗІЙ")
    print("=" * 60)
    print(f"| {'k (біти)':<10} | {'Середній час (мс)':<18} | {'Кількість спроб':<16} |")
    print(f"|{'-' * 12}|{'-' * 20}|{'-' * 18}|")

    for k in range(5, 16):
        total_time = 0.0
        shift = 256 - k
        attempts = 100

        for _ in range(attempts):
            seen: Dict[int, bytes] = {}
            start_time = time.perf_counter()

            while True:
                msg = os.urandom(8)
                h = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
                prefix = h >> shift

                if prefix in seen and seen[prefix] != msg:
                    break

                seen[prefix] = msg

            total_time += (time.perf_counter() - start_time)

        avg_time_ms = (total_time / attempts) * 1000
        print(f"| {k:<10} | {avg_time_ms:<18.4f} | {attempts:<16} |")
    print("-" * 54)