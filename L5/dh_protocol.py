import random

def diffie_hellman_protocol(p, a):
    print(f"\n--- Протокол Діффі-Хеллмана ---")
    print(f"Публічні параметри: p = {p}, a (генератор) = {a}")

    x_A = random.randint(2, p - 2)
    y_A = pow(a, x_A, p)
    print(f"Аліса генерує приватний ключ: {x_A}, публічний: {y_A}")

    x_B = random.randint(2, p - 2)
    y_B = pow(a, x_B, p)
    print(f"Боб генерує приватний ключ: {x_B}, публічний: {y_B}")

    secret_Alice = pow(y_B, x_A, p)
    secret_Bob = pow(y_A, x_B, p)

    print(f"Аліса обчислює спільний секрет: {secret_Alice}")
    print(f"Боб обчислює спільний секрет: {secret_Bob}")

    return secret_Alice, secret_Bob