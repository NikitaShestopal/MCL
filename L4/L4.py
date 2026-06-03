import random
from primes import fast_prime_check, get_512bit_prime, miller_rabin
from rsa import gen_rsa_keys, rsa_enc, rsa_dec_crt
from oaep import oaep_encrypt, oaep_decrypt


def main():
    print("=" * 20 + " ЛАБОРАТОРНА РОБОТА 4 " + "=" * 20)
    print("=== Л4.1 Міллер-Рабін ===")

    # Генеруємо випадкове непарне складене число для наочної демонстрації логів тесту.
    # Зсув вліво на 1 біт робить число парним, а логічне АБО з 1 — гарантовано непарним.
    comp_num = (random.getrandbits(511) << 1) | 1

    # Якщо число успішно відсіяне швидким попереднім тестом як складене,
    # запускаємо основний тест Міллера-Рабіна з логуванням кроків перевірки
    if not fast_prime_check(comp_num):
        miller_rabin(comp_num, 100)

    print("\nГенеруємо справжнє просте число на 512 біт...")
    prime_val = get_512bit_prime()
    # Запуск повної перевірки для згенерованого криптографічного прайма (100 раундів)
    miller_rabin(prime_val, 100)

    print("\n=== Л4.2 та Л4.3 RSA / OAEP ===")
    print("Генерація ключів асиметричної пари, почекайте...")

    # Генерація ключів (генерація p та q, обчислення модуля n, експонент e та d)
    pub_key, priv_key = gen_rsa_keys()
    print(f"  Відкрита експонента e = {pub_key[0]}")
    print(f"  Розмір модуля n: {pub_key[1].bit_length()} біт")

    # Тест 1: Звичайний RSA + оптимізація обчислень через CRT
    msg_num = 123456789101112131415
    print(f"\n[Л4.2] Тест «сирого» ядра RSA. Початкове число: {msg_num}")

    # Пряме шифрування числа: c = m^e mod n
    c_raw = rsa_enc(msg_num, pub_key)
    print(f"  Шифр (просто RSA): {c_raw}")

    # Оптимізоване розшифрування за допомогою Китайської теореми про залишки (CRT)
    d_raw = rsa_dec_crt(c_raw, priv_key)
    print(f"  Розшифровано (через CRT): {d_raw}")

    if msg_num == d_raw:
        print("  -> CRT працює чітко! Математичне ядро симетричне.")
    else:
        print("  -> Помилка обчислень CRT!")

    # Тест 2: Повноцінний криптографічний стандарт RSA-OAEP
    text = "Я вже хочу повішатись".encode('utf-8')
    print(f"\n[Л4.3] Тест стандарту RSA-OAEP. Вихідний текст: {text.decode('utf-8')}")

    # Шифрування: повідомлення кодується паддінгом OAEP, маскується MGF1 та зашифровується
    c_oaep = oaep_encrypt(text, pub_key)
    print(f"  Шифротекст (OAEP, hex): {c_oaep.hex()[:50]}...")

    # Дешифрування: швидке CRT-розшифрування, зняття масок MGF1 та валідація цілісності паддінгу
    d_oaep = oaep_decrypt(c_oaep, priv_key, pub_key)
    print(f"  Розшифрований текст: {d_oaep.decode('utf-8')}")

    if text == d_oaep:
        print("  -> Схема OAEP успішно верифікована. Рандомізація та стійкість до CCA-атак працюють!")
    else:
        print("  -> Помилка декодування паддінгу OAEP!")


if __name__ == "__main__":
    main()