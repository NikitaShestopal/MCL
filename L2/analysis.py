import os
import random
from concurrent.futures import ProcessPoolExecutor
from aes import AES
from utils import count_bit_diff


def run_avalanche_chunk(key_size, chunk_size, rounds_override):
    """
    Автономна робоча функція для обчислення лавинного ефекту на окремому ядрі процесора.
    Генерує випадкові вектори та збирає сумарну відстань Геммінга для своєї порції даних (chunk).
    """
    diff_pt = 0
    diff_key = 0
    bit_masks = [1 << i for i in range(8)] # Маски для інверсії бітів від 0 до 7

    for _ in range(chunk_size):
        # 1. Генерація криптографічно стійких випадкових даних для експерименту
        key = os.urandom(key_size)
        pt = os.urandom(16)

        # Еталонне шифрування блоку
        aes = AES(key, rounds_override)
        c0 = aes.encrypt_block(pt)

        # 2. Дослідження зміни відкритого тексту (Plaintext)
        pt_flipped = bytearray(pt)
        # Інвертуємо рівно 1 випадковий біт в одному випадковому байті тексту
        pt_flipped[random.randint(0, 15)] ^= random.choice(bit_masks)
        c1 = aes.encrypt_block(bytes(pt_flipped))
        # Фіксація кількості змінених бітів у шифротексті
        diff_pt += count_bit_diff(c0, c1)

        # 3. Дослідження зміни ключа шифрування (Cipher Key)
        key_flipped = bytearray(key)
        # Інвертуємо рівно 1 випадковий біт у початковому ключі
        key_flipped[random.randint(0, key_size - 1)] ^= random.choice(bit_masks)
        aes_flipped_key = AES(bytes(key_flipped), rounds_override)
        c2 = aes_flipped_key.encrypt_block(pt)
        # Фіксація відмінностей
        diff_key += count_bit_diff(c0, c2)

    return diff_pt, diff_key


def test_avalanche_effect(key_size, trials=1000, rounds_override=None):
    """
    Багатопроцесорний менеджер тестів лавинного ефекту.
    Розподіляє загальну кількість симуляцій (trials) між доступними CPU ядрами.
    """
    num_workers = os.cpu_count() or 4
    chunk_size = trials // num_workers
    rem = trials % num_workers

    # Рівномірне розбиття випробувань на підзадачі (chunks)
    chunks = [chunk_size] * num_workers
    if rem:
        chunks[0] += rem

    diff_pt_total = 0
    diff_key_total = 0

    # Запуск паралельних обчислень у пулі процесів для уникнення блокувань через GIL в Python
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(run_avalanche_chunk, key_size, c, rounds_override)
            for c in chunks
        ]

        # Агрегація результатів після завершення роботи всіх потоків
        for future in futures:
            pt_diff, key_diff = future.result()
            diff_pt_total += pt_diff
            diff_key_total += key_diff

    # Повертаємо математичне очікування (середнє значення) змінених бітів шифротексту
    return diff_pt_total / trials, diff_key_total / trials