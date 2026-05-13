from constants import SBOX, INV_SBOX, RCON
from utils import gf_mult

class AES:
    def __init__(self, key, rounds_override=None):
        self.key = key
        key_len = len(key)
        if key_len == 16:
            self.Nk = 4; self.Nr = 10
        elif key_len == 24:
            self.Nk = 6; self.Nr = 12
        elif key_len == 32:
            self.Nk = 8; self.Nr = 14
        else:
            raise ValueError("Довжина ключа має бути 16, 24 або 32 байти")

        if rounds_override is not None:
            self.Nr = rounds_override

        self.w = self.key_expansion()

    def key_expansion(self):
        w = list(self.key)
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = w[(i - 1) * 4: i * 4]
            if i % self.Nk == 0:
                temp = temp[1:] + temp[:1]  # RotWord
                temp = [SBOX[b] for b in temp]  # SubWord
                temp[0] ^= RCON[i // self.Nk]  # Rcon
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = [SBOX[b] for b in temp]

            for j in range(4):
                w.append(w[(i - self.Nk) * 4 + j] ^ temp[j])
        return w

    def add_round_key(self, state, round_idx):
        for i in range(16):
            state[i] ^= self.w[round_idx * 16 + i]

    def sub_bytes(self, state):
        for i in range(16): state[i] = SBOX[state[i]]

    def inv_sub_bytes(self, state):
        for i in range(16): state[i] = INV_SBOX[state[i]]

    def shift_rows(self, state):
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    def inv_shift_rows(self, state):
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    def mix_columns(self, state):
        for i in range(4):
            c = i * 4
            s0, s1, s2, s3 = state[c], state[c + 1], state[c + 2], state[c + 3]
            state[c] = gf_mult(2, s0) ^ gf_mult(3, s1) ^ s2 ^ s3
            state[c + 1] = s0 ^ gf_mult(2, s1) ^ gf_mult(3, s2) ^ s3
            state[c + 2] = s0 ^ s1 ^ gf_mult(2, s2) ^ gf_mult(3, s3)
            state[c + 3] = gf_mult(3, s0) ^ s1 ^ s2 ^ gf_mult(2, s3)

    def inv_mix_columns(self, state):
        for i in range(4):
            c = i * 4
            s0, s1, s2, s3 = state[c], state[c + 1], state[c + 2], state[c + 3]
            state[c] = gf_mult(0x0e, s0) ^ gf_mult(0x0b, s1) ^ gf_mult(0x0d, s2) ^ gf_mult(0x09, s3)
            state[c + 1] = gf_mult(0x09, s0) ^ gf_mult(0x0e, s1) ^ gf_mult(0x0b, s2) ^ gf_mult(0x0d, s3)
            state[c + 2] = gf_mult(0x0d, s0) ^ gf_mult(0x09, s1) ^ gf_mult(0x0e, s2) ^ gf_mult(0x0b, s3)
            state[c + 3] = gf_mult(0x0b, s0) ^ gf_mult(0x0d, s1) ^ gf_mult(0x09, s2) ^ gf_mult(0x0e, s3)

    def encrypt_block(self, plaintext):
        state = list(plaintext)
        self.add_round_key(state, 0)

        for r in range(1, self.Nr):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, r)

        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.Nr)
        return bytes(state)

    def decrypt_block(self, ciphertext):
        state = list(ciphertext)
        self.add_round_key(state, self.Nr)
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)

        for r in range(self.Nr - 1, 0, -1):
            self.add_round_key(state, r)
            self.inv_mix_columns(state)
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)

        self.add_round_key(state, 0)
        return bytes(state)