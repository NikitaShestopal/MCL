from utils import ALPHABET, clean_text


def vigenere_encrypt(plaintext, key):
    """
    Шифрує відкритий текст за допомогою ключа методом Віженера.
    Формула: C_i = (P_i + K_i) % N
    """
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    ciphertext = []

    # Ітеруємося по кожному символу відкритого тексту
    for i, char in enumerate(plaintext):
        p_idx = ALPHABET.index(char)  # Індекс символу відкритого тексту
        k_idx = ALPHABET.index(key[i % len(key)])  # Індекс відповідного символу ключа (циклічно)

        # Зсув символу в межах розміру алфавіту
        c_idx = (p_idx + k_idx) % len(ALPHABET)
        ciphertext.append(ALPHABET[c_idx])

    return ''.join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    """
    Розшифровує зашифрований текст за допомогою ключа методом Віженера.
    Формула: P_i = (C_i - K_i + N) % N
    """
    ciphertext = clean_text(ciphertext)
    key = clean_text(key)
    plaintext = []

    # Ітеруємося по кожному символу зашифрованого тексту
    for i, char in enumerate(ciphertext):
        c_idx = ALPHABET.index(char)  # Індекс символу шифротексту
        k_idx = ALPHABET.index(key[i % len(key)])  # Індекс відповідного символу ключа

        # Зворотний зсув для відновлення відкритого тексту
        p_idx = (c_idx - k_idx) % len(ALPHABET)
        plaintext.append(ALPHABET[p_idx])

    return ''.join(plaintext)