import os
from aes import AES
from utils import flip_random_bit, count_bit_diff

def test_avalanche_effect(key_size, trials=1000, rounds_override=None):
    diff_pt_total = 0
    diff_key_total = 0

    for _ in range(trials):
        key = os.urandom(key_size)
        pt = os.urandom(16)

        aes = AES(key, rounds_override)
        c0 = aes.encrypt_block(pt)

        pt_flipped = flip_random_bit(pt)
        c1 = aes.encrypt_block(pt_flipped)
        diff_pt_total += count_bit_diff(c0, c1)

        key_flipped = flip_random_bit(key)
        aes_flipped_key = AES(key_flipped, rounds_override)
        c2 = aes_flipped_key.encrypt_block(pt)
        diff_key_total += count_bit_diff(c0, c2)

    avg_pt_diff = diff_pt_total / trials
    avg_key_diff = diff_key_total / trials
    return avg_pt_diff, avg_key_diff