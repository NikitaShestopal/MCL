import os
import hashlib
from rsa import rsa_dec_crt

def xor_b(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def mgf1(seed, length, hash_alg=hashlib.sha256):
    T = b""
    counter = 0
    while len(T) < length:
        C = counter.to_bytes(4, "big")
        T += hash_alg(seed + C).digest()
        counter += 1
    return T[:length]

def oaep_encrypt(m_bytes, pub, hash_alg=hashlib.sha256):
    e, n = pub
    k = (n.bit_length() + 7) // 8
    h_len = hash_alg().digest_size

    if len(m_bytes) > k - 2 * h_len - 2:
        raise ValueError("Повідомлення завелике для цього модуля")

    l_hash = hash_alg(b"").digest()
    ps = b"\x00" * (k - len(m_bytes) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + m_bytes

    seed = os.urandom(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_alg)
    masked_db = xor_b(db, db_mask)

    seed_mask = mgf1(masked_db, h_len, hash_alg)
    masked_seed = xor_b(seed, seed_mask)

    em = b"\x00" + masked_seed + masked_db

    m_int = int.from_bytes(em, "big")
    c_int = pow(m_int, e, n)
    return c_int.to_bytes(k, "big")

def oaep_decrypt(c_bytes, priv, pub, hash_alg=hashlib.sha256):
    _, n = pub
    k = (n.bit_length() + 7) // 8
    h_len = hash_alg().digest_size

    c_int = int.from_bytes(c_bytes, "big")
    m_int = rsa_dec_crt(c_int, priv)

    em = m_int.to_bytes(k, "big")

    if em[0] != 0:
        raise ValueError("Дешифрування: помилка в першому байті")

    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]

    seed_mask = mgf1(masked_db, h_len, hash_alg)
    seed = xor_b(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - h_len - 1, hash_alg)
    db = xor_b(masked_db, db_mask)

    l_hash = hash_alg(b"").digest()
    if db[:h_len] != l_hash:
        raise ValueError("Дешифрування: хеші не співпадають")

    for i in range(h_len, len(db)):
        if db[i] == 1:
            return db[i + 1:]
        elif db[i] != 0:
            raise ValueError("Дешифрування: кривий padding")

    raise ValueError("Дешифрування: не знайшли маркер початку")