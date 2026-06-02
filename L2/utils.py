import random

GF_MULT_2 = [0] * 256
GF_MULT_3 = [0] * 256

for i in range(256):
    hi_bit = i & 0x80
    val2 = (i << 1) & 0xFF
    if hi_bit:
        val2 ^= 0x1B
    GF_MULT_2[i] = val2
    GF_MULT_3[i] = val2 ^ i

def gf_mult(a, b):
    if a == 2: return GF_MULT_2[b]
    if a == 3: return GF_MULT_3[b]
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set: a ^= 0x1B
        b >>= 1
    return p % 256

def flip_random_bit(data: bytes) -> bytes:
    data_list = bytearray(data)
    byte_idx = random.randint(0, len(data_list) - 1)
    bit_idx = random.randint(0, 7)
    data_list[byte_idx] ^= (1 << bit_idx)
    return bytes(data_list)

def count_bit_diff(b1: bytes, b2: bytes) -> int:
    diff = 0
    for byte1, byte2 in zip(b1, b2):
        diff += bin(byte1 ^ byte2).count('1')
    return diff