from utils import ALPHABET, clean_text

def vigenere_encrypt(plaintext, key):
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    ciphertext = []

    for i, char in enumerate(plaintext):
        p_idx = ALPHABET.index(char)
        k_idx = ALPHABET.index(key[i % len(key)])
        c_idx = (p_idx + k_idx) % len(ALPHABET)
        ciphertext.append(ALPHABET[c_idx])

    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    ciphertext = clean_text(ciphertext)
    key = clean_text(key)
    plaintext = []

    for i, char in enumerate(ciphertext):
        c_idx = ALPHABET.index(char)
        k_idx = ALPHABET.index(key[i % len(key)])
        p_idx = (c_idx - k_idx) % len(ALPHABET)
        plaintext.append(ALPHABET[p_idx])

    return ''.join(plaintext)