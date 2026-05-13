from discrete_log import find_generator, bsgs
from dh_protocol import diffie_hellman_protocol


def main():
    p = 1048573

    print(f"=== Л5.1 Пошук генератора ===")
    g = find_generator(p)
    print(f"Для простого числа p = {p}")
    print(f"Знайдено твірний елемент (генератор) a = {g}")

    print("\n=== Л5.2 Алгоритм BSGS (Криптоаналіз) ===")
    x_target = 987654
    h = pow(g, x_target, p)
    print(f"Задача: знайти x у рівнянні {g}^x ≡ {h} (mod {p})")

    print("Запуск алгоритму малих і великих кроків...")
    x_found = bsgs(g, h, p)
    print(f"Знайдений показник x = {x_found}")

    if x_found == x_target:
        print("Результат вірний! Алгоритм працює правильно.")
    else:
        print("Помилка: результати не збігаються.")

    print("\n=== Л5.3 Протокол Діффі-Хеллмана ===")
    s1, s2 = diffie_hellman_protocol(p, g)

    if s1 == s2:
        print("\nУспіх! Спільний секретний ключ встановлено.")
        print(f"Фінальний секретний ключ K = {s1}")
    else:
        print("\nКритична помилка: ключі сторін різняться!")


if __name__ == "__main__":
    main()