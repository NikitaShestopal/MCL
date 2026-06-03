import struct
from constants import SHA256_K, INITIAL_HASH_VALUES


def _right_rotate(n: int, b: int) -> int:
    """
    Виконує циклічний зсув (циклічне праворуч) 32-бітного беззнакового цілого числа 'n' на 'b' бітів.
    """
    return ((n >> b) | (n << (32 - b))) & 0xffffffff


def sha256_custom(message: bytes) -> bytes:
    """
    Кастомна імплементація SHA-256 згідно зі специфікацією FIPS 180-4.
    Приймає масив байтів, повертає 32-байтний (256-бітний) дайджест.
    """
    # Ініціалізація внутрішніх регістрів початковими константами
    h0, h1, h2, h3, h4, h5, h6, h7 = INITIAL_HASH_VALUES

    # Етап 1: Доповнення повідомлення (Padding)
    original_bit_len = len(message) * 8
    message += b'\x80'  # Додаємо обов'язковий роздільний біт "1" (байт 10000000)

    # Доповнюємо нульовими байтами, залишаючи в кінці 64 біти (8 байт) для запису довжини
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    # Записуємо оригінальну довжину повідомлення у бітах як 64-бітне ціле число (Big-Endian Q)
    message += struct.pack('>Q', original_bit_len)

    # Етап 2: Ітеративна обробка блоків по 512 біт (64 байти)
    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]

        # Розпаковуємо перші 16 слів по 4 байти (Big-Endian L) і створюємо робочий масив на 64 слова
        w = list(struct.unpack('>16L', chunk)) + [0] * 48

        # Генерація Message Schedule: розширення 16 слів у 64 за допомогою лінійних функцій
        for j in range(16, 64):
            # Малі логічні функції зсуву сигма-0 та сигма-1
            s0 = _right_rotate(w[j - 15], 7) ^ _right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = _right_rotate(w[j - 2], 17) ^ _right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
            # Нове слово — це каскадне додавання попередніх елементів за модулем 2^32
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xffffffff

        # Ініціалізація локальних змінних раунду поточним станом хешу
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        # Етап 3: Головний цикл стиснення (64 раунди)
        for j in range(64):
            # Великі логічні функції Sigma1 та Choice для регістра 'e'
            S1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            # Обчислення першого тимчасового слова (накопичує нелінійну інформацію нижньої половини)
            temp1 = (h + S1 + ch + SHA256_K[j] + w[j]) & 0xffffffff

            # Великі логічні функції Sigma0 та Majority для регістра 'a'
            S0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            # Обчислення другого тимчасового слова (структурує інформацію верхньої половини)
            temp2 = (S0 + maj) & 0xffffffff

            # Каскадний зсув внутрішніх змінних. Значення 'd' та 'a' оновлюються сумами з temp
            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & 0xffffffff, c, b, a, (temp1 + temp2) & 0xffffffff
            )

        # Додавання результатів обробки поточного блоку до глобального стану (структура Меркла-Дамґорда)
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    # Пакування фінальних 8 слів по 4 байти у підсумковий 32-байтний рядок
    return struct.pack('>8L', h0, h1, h2, h3, h4, h5, h6, h7)