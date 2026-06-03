import os
import hashlib
from rsa import rsa_dec_crt


def xor_b(a, b):
    """
    Виконує побітову операцію XOR для двох байтових рядків однакової довжини.

    Математичний сенс: використовується як симетричний засіб накладання
    та зняття маски (оскільки A ^ B ^ B = A).
    """
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed, length, hash_alg=hashlib.sha256):
    """
    Функція генерації маски MGF1 (Mask Generation Function 1) згідно зі стандартом PKCS #1.

    Призначення: Розвертає короткий випадковий рядок (seed) у детерміновану
    псевдовипадкову послідовність байтів заданої довжини (length).
    Алгоритм ітеративно хешує seed разом із 4-байтним лічильником C.
    """
    T = b""
    counter = 0
    while len(T) < length:
        # Конвертуємо поточний лічильник у 4-байтне представлення Big-Endian
        C = counter.to_bytes(4, "big")
        # Конкатенуємо seed з лічильником і додаємо дайджест до загальної маски
        T += hash_alg(seed + C).digest()
        counter += 1
    # Повертаємо маску, обрізану до точної необхідної довжини
    return T[:length]


def oaep_encrypt(m_bytes, pub, hash_alg=hashlib.sha256):
    """
    Зашифрування повідомлення за схемою RSA-OAEP (Optimal Asymmetric Encryption Padding).

    OAEP перетворює детерміновану систему RSA на імовірнісну. Це захищає від
    атак на основі підібраного шифротексту (CCA) завдяки дворівневій мережі Фейстеля.
    """
    e, n = pub
    # k — довжина модуля RSA в байтах (наприклад, 128 байт для 1024-бітного ключа)
    k = (n.bit_length() + 7) // 8
    h_len = hash_alg().digest_size

    # Перевірка обмеження: довжина повідомлення не повинна перевищувати k - 2*h_len - 2
    if len(m_bytes) > k - 2 * h_len - 2:
        raise ValueError("Повідомлення завелике для цього модуля")

    # Крок 1: Формування блоку даних (DB = lHash || PS || 0x01 || M)
    l_hash = hash_alg(b"").digest()  # Хеш порожньої мітки (Label) за замовчуванням
    # PS (Padding String) — рядок із нульових байтів для заповнення простору, що залишився
    ps = b"\x00" * (k - len(m_bytes) - 2 * h_len - 2)
    # Збирання DB: маркер 0x01 відділяє паддінг від самого повідомлення
    db = l_hash + ps + b"\x01" + m_bytes

    # Крок 2: Генерація випадкового зерна криптографічної довжини (рівної h_len)
    seed = os.urandom(h_len)

    # Крок 3: Обчислення маски для блоку даних та маскування DB
    db_mask = mgf1(seed, k - h_len - 1, hash_alg)
    masked_db = xor_b(db, db_mask)

    # Крок 4: Обчислення маски для зерна на основі masked_db та маскування самого зерна
    seed_mask = mgf1(masked_db, h_len, hash_alg)
    masked_seed = xor_b(seed, seed_mask)

    # Крок 5: Формування фінального закодованого повідомлення EM (Encoded Message)
    # Перший байт завжди 0x00 згідно зі стандартом для гарантії, що EM < n математично
    em = b"\x00" + masked_seed + masked_db

    # Крок 6: Математичне асиметричне шифрування сформованого блоку
    m_int = int.from_bytes(em, "big")
    c_int = pow(m_int, e, n)
    return c_int.to_bytes(k, "big")


def oaep_decrypt(c_bytes, priv, pub, hash_alg=hashlib.sha256):
    """
    Розшифрування шифротексту за схемою RSA-OAEP та сувора перевірка структури паддінгу.

    Будь-яка невідповідність структури байтів або міток викликає помилку декодування.
    Це запобігає атакам за побічними каналами (наприклад, атаці Блейхенбахера).
    """
    _, n = pub
    k = (n.bit_length() + 7) // 8
    h_len = hash_alg().digest_size

    # Крок 1: Математичне дешифрування з використанням швидкої схеми CRT
    c_int = int.from_bytes(c_bytes, "big")
    m_int = rsa_dec_crt(c_int, priv)

    # Перетворення розшифрованого великого числа назад у байтовий блок EM
    em = m_int.to_bytes(k, "big")

    # Валідація: Стандартизований перший байт обов'язково має бути 0x00
    if em[0] != 0:
        raise ValueError("Дешифрування: помилка в першому байті")

    # Розподіл блоку EM на замасковане зерно та замаскований блок даних
    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]

    # Крок 2: Зняття маски з masked_seed за допомогою маски, згенерованої від masked_db
    seed_mask = mgf1(masked_db, h_len, hash_alg)
    seed = xor_b(masked_seed, seed_mask)

    # Крок 3: Зняття маски з masked_db за допомогою маски, згенерованої від відновленого seed
    db_mask = mgf1(seed, k - h_len - 1, hash_alg)
    db = xor_b(masked_db, db_mask)

    # Крок 4: Валідація цілісності мітки lHash
    l_hash = hash_alg(b"").digest()
    if db[:h_len] != l_hash:
        raise ValueError("Дешифрування: хеші не співпадають")

    # Крок 5: Парсинг паддінгу та пошук маркера початку корисних даних (0x01)
    # Пропускаємо нульові байти рядка доповнення PS
    for i in range(h_len, len(db)):
        if db[i] == 1:
            # Маркер 0x01 знайдено. Все, що знаходиться після нього — це оригінальне повідомлення
            return db[i + 1:]
        elif db[i] != 0:
            # Якщо замість 0x00 або 0x01 виявлено інший байт — паддінг пошкоджено
            raise ValueError("Дешифрування: кривий padding")

    raise ValueError("Дешифрування: не знайшли маркер початку")