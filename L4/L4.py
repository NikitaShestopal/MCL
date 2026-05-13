# L4.py
import random
from primes import fast_prime_check, get_512bit_prime, miller_rabin
from rsa import gen_rsa_keys, rsa_enc, rsa_dec_crt
from oaep import oaep_encrypt, oaep_decrypt

def main():
    print("=== Л4.1 Міллер-Рабін ===")

    # Тестове складене число
    comp_num = (random.getrandbits(511) << 1) | 1
    if not fast_prime_check(comp_num):
        miller_rabin(comp_num, 100)

    print("\nГенеруємо просте число на 512 біт...")
    prime_val = get_512bit_prime()
    miller_rabin(prime_val, 100)

    print("\n=== Л4.2 та Л4.3 RSA / OAEP ===")
    print("Генерація ключів, почекайте...")

    pub_key, priv_key = gen_rsa_keys()
    print(f"Відкрита експонента e = {pub_key[0]}")
    print(f"Розмір n: {pub_key[1].bit_length()} біт")

    # Тест 1: Звичайний RSA + CRT
    msg_num = 123456789101112131415
    print(f"\n[Л4.2] Початкове число: {msg_num}")

    c_raw = rsa_enc(msg_num, pub_key)
    print(f"Шифр (просто RSA): {c_raw}")

    d_raw = rsa_dec_crt(c_raw, priv_key)
    print(f"Розшифровано (через CRT): {d_raw}")

    if msg_num == d_raw:
        print("-> CRT працює чітко!")
    else:
        print("-> Помилка CRT!")

    # Тест 2: RSA-OAEP
    text = "Я вже хочу повішатись".encode('utf-8')
    print(f"\n[Л4.3] Текст: {text.decode('utf-8')}")

    c_oaep = oaep_encrypt(text, pub_key)
    print(f"Шифр (OAEP, hex): {c_oaep.hex()[:50]}...")

    d_oaep = oaep_decrypt(c_oaep, priv_key, pub_key)
    print(f"Розшифрований текст: {d_oaep.decode('utf-8')}")

    if text == d_oaep:
        print("-> OAEP зашифрований")
    else:
        print("-> Помилка OAEP!")

if __name__ == "__main__":
    main()