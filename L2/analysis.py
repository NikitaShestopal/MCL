import os
import random
from concurrent.futures import ProcessPoolExecutor
from aes import AES
from utils import count_bit_diff


def run_avalanche_chunk(key_size, chunk_size, rounds_override):
    diff_pt = 0
    diff_key = 0
    bit_masks = [1 << i for i in range(8)]

    for _ in range(chunk_size):
        key = os.urandom(key_size)
        pt = os.urandom(16)

        aes = AES(key, rounds_override)
        c0 = aes.encrypt_block(pt)

        pt_flipped = bytearray(pt)
        pt_flipped[random.randint(0, 15)] ^= random.choice(bit_masks)

        c1 = aes.encrypt_block(bytes(pt_flipped))
        diff_pt += count_bit_diff(c0, c1)

        key_flipped = bytearray(key)
        key_flipped[random.randint(0, key_size - 1)] ^= random.choice(bit_masks)

        aes_flipped_key = AES(bytes(key_flipped), rounds_override)
        c2 = aes_flipped_key.encrypt_block(pt)
        diff_key += count_bit_diff(c0, c2)

    return diff_pt, diff_key


def test_avalanche_effect(key_size, trials=1000, rounds_override=None):
    num_workers = os.cpu_count() or 4
    chunk_size = trials // num_workers
    rem = trials % num_workers

    chunks = [chunk_size] * num_workers
    if rem:
        chunks[0] += rem

    diff_pt_total = 0
    diff_key_total = 0

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(run_avalanche_chunk, key_size, c, rounds_override)
            for c in chunks
        ]

        for future in futures:
            pt_diff, key_diff = future.result()
            diff_pt_total += pt_diff
            diff_key_total += key_diff

    return diff_pt_total / trials, diff_key_total / trials