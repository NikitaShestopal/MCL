import collections
from utils import ALPHABET, UKRAINIAN_FREQS
from task2 import vigenere_decrypt


def calculate_ic(text):
    """
    Обчислює індекс збігу (Index of Coincidence) для заданого тексту.
    Показує ймовірність того, що два випадково обрані символи є однаковими.
    """
    n = len(text)
    if n <= 1:
        return 0

    freqs = collections.Counter(text)
    # Сума за формулою: f * (f - 1) для кожної літери
    ic = sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))
    return ic


def find_key_length(ciphertext, min_len=2, max_len=15):
    """
    Визначає найбільш ймовірну довжину ключа методом тесту узагальненого індексу збігу.
    Розбиває текст на стовпчики відповідно до довжини і шукає сплеск значення IC.
    """
    best_len = 0
    best_ic = 0

    print(f"{'Довжина':<10} | {'Середній IC':<10}")
    print("-" * 25)

    # Перевіряємо припущення щодо довжини ключа в заданому діапазоні
    for length in range(min_len, max_len + 1):
        ics = []
        # Розбиваємо текст на `length` окремих стовпчиків (як у шифрі Цезаря)
        for i in range(length):
            column = ciphertext[i::length]  # Беремо кожен i-й символ з кроком length
            ics.append(calculate_ic(column))

        # Рахуємо середній індекс збігу для поточної довжини ключа
        avg_ic = sum(ics) / len(ics)
        print(f"{length:<10} | {avg_ic:.5f}")

        # Зберігаємо довжину, яка дає найбільше значення IC (найближче до природної мови)
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = length

    print(f"\n=> Найбільш ймовірна довжина ключа: {best_len} (IC = {best_ic:.5f})")
    return best_len


def calculate_chi_squared(text):
    """
    Обчислює статистику Хі-квадрат (Chi-squared) для порівняння
    розподілу літер у тексті зі стандартним розподілом української мови.
    """
    n = len(text)
    freqs = collections.Counter(text)
    chi_sq = 0

    for char in ALPHABET:
        observed = freqs.get(char, 0)  # Скільки разів літера зустрілася фактично
        expected = n * UKRAINIAN_FREQS[char]  # Скільки разів вона мала б зустрітися теоретично

        # Обчислення за стандартною статистичною формулою: ((O - E)^2) / E
        if expected > 0:
            chi_sq += ((observed - expected) ** 2) / expected

    return chi_sq


def find_key(ciphertext, key_length):
    """
    Бере кожен стовпчик шифротексту як окремий шифр Цезаря.
    Знаходить символ ключа, який дає найменше значення Хі-квадрат при дешифруванні.
    """
    key = ""
    # Аналізуємо кожен символ ключа окремо за його позицією
    for i in range(key_length):
        column = ciphertext[i::key_length]  # Виокремлюємо стовпчик символів
        best_shift = 0
        min_chi_sq = float('inf')

        # Перебираємо всі можливі зсуви алфавіту (для пошуку конкретної літери ключа)
        for shift in range(len(ALPHABET)):
            # Пробуємо розшифрувати стовпчик поточною літерою (літера за індексом shift)
            decrypted_col = vigenere_decrypt(column, ALPHABET[shift])
            # Оцінюємо, наскільки отриманий текст схожий на реальну мову
            chi_sq = calculate_chi_squared(decrypted_col)

            # Що менше значення хі-квадрат, то ближчий розподіл до природної мови
            if chi_sq < min_chi_sq:
                min_chi_sq = chi_sq
                best_shift = shift

        # Додаємо знайдену літеру до фінального ключа
        key += ALPHABET[best_shift]

    print(f"\n=> Знайдений ключ: {key}")
    return key