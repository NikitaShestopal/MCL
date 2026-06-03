import random

# Пре-обчислені look-up масиви для прискорення операції MixColumns в реальному часі
GF_MULT_2 = [0] * 256
GF_MULT_3 = [0] * 256

# Ініціалізація таблиць множення на {02} та {03} у полі Галуа GF(2^8) за модулем полінома 0x1B
for i in range(256):
    hi_bit = i & 0x80
    val2 = (i << 1) & 0xFF
    if hi_bit:
        val2 ^= 0x1B  # Редукція незвідним многочленом x^8 + x^4 + x^3 + x + 1
    GF_MULT_2[i] = val2
    GF_MULT_3[i] = val2 ^ i  # Оскільки {03}*x = ({02}*x) XOR ({01}*x)


def gf_mult(a, b):
    """
    Універсальна функція множення двох довільних елементів поля Галуа GF(2^8).
    Використовує оптимізовані табличні значення, якщо множники рівні 2 або 3.
    """
    if a == 2: return GF_MULT_2[b]
    if a == 3: return GF_MULT_3[b]

    p = 0
    # Математичний алгоритм множення "Shift and XOR"
    for _ in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set: a ^= 0x1B
        b >>= 1
    return p % 256


def flip_random_bit(data: bytes) -> bytes:
    """
    Допоміжний метод інверсії (мутації) одного випадкового біта у байтовому масиві.
    """
    data_list = bytearray(data)
    byte_idx = random.randint(0, len(data_list) - 1)
    bit_idx = random.randint(0, 7)
    data_list[byte_idx] ^= (1 << bit_idx)  # Оператор XOR для інверсії конкретного біта
    return bytes(data_list)


def count_bit_diff(b1: bytes, b2: bytes) -> int:
    """
    Обчислює відстань Геммінга між двома послідовностями байтів.
    Рахує сумарну кількість відмінних бітів на однакових позиціях.
    """
    diff = 0
    for byte1, byte2 in zip(b1, b2):
        # Операція XOR залишає одиниці тільки в позиціях відмінностей бітів
        diff += bin(byte1 ^ byte2).count('1')
    return diff