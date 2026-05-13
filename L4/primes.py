# primes.py
import random

def miller_rabin(n, k=100):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    print(f"\n[Завдання 1] Перевірка числа: {n}")

    for i in range(k):
        a = random.randrange(2, n - 1)
        print(f"  Крок {i + 1}: a = {a}")

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            print(f"-> Число складене (знайшли на {i + 1} ітерації)")
            return False

    print(f"-> Можливо просте (всі {k} перевірок пройшли успішно)")
    return True

def fast_prime_check(n, k=40):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def get_512bit_prime():
    while True:
        p = random.getrandbits(512)
        p |= (1 << 511) | 1
        if fast_prime_check(p):
            return p