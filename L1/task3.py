import collections
from utils import ALPHABET, UKRAINIAN_FREQS
from task2 import vigenere_decrypt

def calculate_ic(text):
    n = len(text)
    if n <= 1: return 0
    freqs = collections.Counter(text)
    ic = sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))
    return ic

def find_key_length(ciphertext, min_len=2, max_len=15):
    best_len = 0
    best_ic = 0

    print(f"{'Довжина':<10} | {'Середній IC':<10}")
    print("-" * 25)

    for length in range(min_len, max_len + 1):
        ics = []
        for i in range(length):
            column = ciphertext[i::length]
            ics.append(calculate_ic(column))

        avg_ic = sum(ics) / len(ics)
        print(f"{length:<10} | {avg_ic:.5f}")

        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = length

    print(f"\n=> Найбільш ймовірна довжина ключа: {best_len} (IC = {best_ic:.5f})")
    return best_len

def calculate_chi_squared(text):
    n = len(text)
    freqs = collections.Counter(text)
    chi_sq = 0

    for char in ALPHABET:
        observed = freqs.get(char, 0)
        expected = n * UKRAINIAN_FREQS[char]
        if expected > 0:
            chi_sq += ((observed - expected) ** 2) / expected

    return chi_sq

def find_key(ciphertext, key_length):
    key = ""
    for i in range(key_length):
        column = ciphertext[i::key_length]
        best_shift = 0
        min_chi_sq = float('inf')

        for shift in range(len(ALPHABET)):
            decrypted_col = vigenere_decrypt(column, ALPHABET[shift])
            chi_sq = calculate_chi_squared(decrypted_col)

            if chi_sq < min_chi_sq:
                min_chi_sq = chi_sq
                best_shift = shift

        key += ALPHABET[best_shift]

    print(f"\n=> Знайдений ключ: {key}")
    return key