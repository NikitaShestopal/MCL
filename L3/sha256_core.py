import struct
from constants import SHA256_K, INITIAL_HASH_VALUES

def _right_rotate(n: int, b: int) -> int:
    return ((n >> b) | (n << (32 - b))) & 0xffffffff

def sha256_custom(message: bytes) -> bytes:
    h0, h1, h2, h3, h4, h5, h6, h7 = INITIAL_HASH_VALUES

    original_bit_len = len(message) * 8
    message += b'\x80'

    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', original_bit_len)

    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]
        w = list(struct.unpack('>16L', chunk)) + [0] * 48

        for j in range(16, 64):
            s0 = _right_rotate(w[j - 15], 7) ^ _right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = _right_rotate(w[j - 2], 17) ^ _right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for j in range(64):
            S1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + SHA256_K[j] + w[j]) & 0xffffffff

            S0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & 0xffffffff, c, b, a, (temp1 + temp2) & 0xffffffff
            )

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    return struct.pack('>8L', h0, h1, h2, h3, h4, h5, h6, h7)