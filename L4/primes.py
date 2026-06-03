import random

def miller_rabin(n, k=100):
    """
    Тест Міллера-Рабіна з логуванням кроків перевірки.
    Розкладає n - 1 = 2^s * d. Перевіряє "свідків простоти" а.
    """
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    # Розкладання числа для тестування
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    print(f"\n[Завдання 1] Перевірка числа: {n}")

    # Виконуємо k незалежних раундів тестування
    for i in range(k):
        a = random.randrange(2, n - 1)
        print(f"  Крок {i + 1}: a = {a}")

        # Обчислюємо первинний відбиток: x = a^d mod n
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        composite = True
        # Послідовно підносимо до квадрата s - 1 разів
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False  # Число пройшло раунд (сильне псевдопросте)
                break

        if composite:
            print(f"-> Число складене (знайшли на {i + 1} ітерації)")
            return False

    print(f"-> Можливо просте (всі {k} перевірок пройшли успішно)")
    return True

def fast_prime_check(n, k=40):
    """
    Оптимізована (мовчазна) версія тесту Міллера-Рабіна без виведення в консоль.
    Використовується для швидкої масової фільтрації випадкових чисел при генерації.
    """
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
    """
    Генерує випадкове велике просте число розміром 512 біт.
    Встановлює старший біт у 1 (гарантія розміру) та молодший у 1 (непарність).
    """
    while True:
        p = random.getrandbits(512)
        p |= (1 << 511) | 1  # Накладання бітової маски
        if fast_prime_check(p):
            return p