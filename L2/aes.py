from constants import SBOX, INV_SBOX, RCON
from utils import GF_MULT_2, GF_MULT_3, gf_mult


class AES:
    """
    Клас, що реалізує симетричний алгоритм блочного шифрування AES (Rijndael).
    Підтримує роботу з блоками розміром 128 біт та ключами 128, 192, 256 біт.
    Матриця стану State представлена у вигляді одновимірного масиву з 16 байт (column-major order).
    """

    def __init__(self, key, rounds_override=None):
        self.key = key
        key_len = len(key)

        # Визначення кількості слів ключа (Nk) та кількості раундів (Nr) згідно зі стандартом FIPS 197
        if key_len == 16:
            self.Nk = 4;
            self.Nr = 10  # AES-128
        elif key_len == 24:
            self.Nk = 6;
            self.Nr = 12  # AES-192
        elif key_len == 32:
            self.Nk = 8;
            self.Nr = 14  # AES-256
        else:
            raise ValueError("Довжина ключа має бути 16, 24 або 32 байти")

        # Можливість перевизначити кількість раундів для дослідження динаміки лавинного ефекту
        if rounds_override is not None:
            self.Nr = rounds_override

        # Генерація розширеного масиву раундових ключів (Key Schedule)
        self.w = self.key_expansion()

    def key_expansion(self):
        """
        Розширення початкового ключа шифрування для отримання усього масиву раундових ключів.
        Загальна кількість байт на виході дорівнює 16 * (Nr + 1).
        """
        w = list(self.key)
        # Обчислення раундових ключів ітеративно по 4 байти (одне 32-бітне слово)
        for i in range(self.Nk, 4 * (self.Nr + 1)):
            temp = w[(i - 1) * 4: i * 4]  # Беремо попереднє слово

            # Кожне Nk-те слово піддається нелінійній трансформації
            if i % self.Nk == 0:
                temp = temp[1:] + temp[:1]  # RotWord: циклічний зсув вліво на 1 байт
                temp = [SBOX[b] for b in temp]  # SubWord: байтова заміна через S-Box
                temp[0] ^= RCON[i // self.Nk]  # Rcon: XOR молодшого байта з раундовою константою
            # Додаткова трансформація SubWord для AES-256
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = [SBOX[b] for b in temp]

            # Основна операція XOR: поточне слово = слово на Nk позицій назад XOR temp
            for j in range(4):
                w.append(w[(i - self.Nk) * 4 + j] ^ temp[j])
        return w

    def add_round_key(self, state, round_idx):
        """
        Накладання раундового ключа на матрицю стану State за допомогою операції побітового XOR.
        """
        for i in range(16):
            state[i] ^= self.w[round_idx * 16 + i]

    def sub_bytes(self, state):
        """
        Пряма байтова заміна SubBytes. Забезпечує нелінійність алгоритму AES
        через заміну кожного байта за фіксованою таблицею S-Box.
        """
        for i in range(16): state[i] = SBOX[state[i]]

    def inv_sub_bytes(self, state):
        """
        Обернена байтова заміна InvSubBytes за допомогою таблиці INV_SBOX для дешифрування.
        """
        for i in range(16): state[i] = INV_SBOX[state[i]]

    def shift_rows(self, state):
        """
        Циклічний зсув рядків матриці стану State вліво.
        Оскільки стан одновимірний (за стовпчиками), індекси рядків розподілені так:
        Рядок 0: 0, 4, 8, 12  -> без зсуву
        Рядок 1: 1, 5, 9, 13  -> зсув вліво на 1
        Рядок 2: 2, 6, 10, 14 -> зсув вліво на 2
        Рядок 3: 3, 7, 11, 15 -> зсув вліво на 3
        """
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    def inv_shift_rows(self, state):
        """
        Обернений циклічний зсув рядків матриці стану State вправо для процесу дешифрування.
        """
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    def mix_columns(self, state):
        """
        Перемішування стовпчиків MixColumns. Кожен стовпчик розглядається як поліном
        над полем GF(2^8) і множиться за модулем x^4 + 1 на фіксовану матрицю.
        Реалізовано з використанням оптимізованих Look-up таблиць GF_MULT_2 та GF_MULT_3.
        """
        for i in range(4):
            c = i * 4  # Базовий зміщення для i-го стовпчика
            s0, s1, s2, s3 = state[c], state[c + 1], state[c + 2], state[c + 3]
            state[c] = GF_MULT_2[s0] ^ GF_MULT_3[s1] ^ s2 ^ s3
            state[c + 1] = s0 ^ GF_MULT_2[s1] ^ GF_MULT_3[s2] ^ s3
            state[c + 2] = s0 ^ s1 ^ GF_MULT_2[s2] ^ GF_MULT_3[s3]
            state[c + 3] = GF_MULT_3[s0] ^ s1 ^ s2 ^ GF_MULT_2[s3]

    def inv_mix_columns(self, state):
        """
        Обернене перемішування стовпчиків InvMixColumns. Множення виконується на обернену
        матрицю з коефіцієнтами 0x0E, 0x0B, 0x0D, 0x09 через загальну функцію gf_mult.
        """
        for i in range(4):
            c = i * 4
            s0, s1, s2, s3 = state[c], state[c + 1], state[c + 2], state[c + 3]
            state[c] = gf_mult(0x0e, s0) ^ gf_mult(0x0b, s1) ^ gf_mult(0x0d, s2) ^ gf_mult(0x09, s3)
            state[c + 1] = gf_mult(0x09, s0) ^ gf_mult(0x0e, s1) ^ gf_mult(0x0b, s2) ^ gf_mult(0x0d, s3)
            state[c + 2] = gf_mult(0x0d, s0) ^ gf_mult(0x09, s1) ^ gf_mult(0x0e, s2) ^ gf_mult(0x0b, s3)
            state[c + 3] = gf_mult(0x0b, s0) ^ gf_mult(0x0d, s1) ^ gf_mult(0x09, s2) ^ gf_mult(0x0e, s3)

    def encrypt_block(self, plaintext):
        """
        Шифрування одного 16-байтного блоку даних.
        """
        state = list(plaintext)
        self.add_round_key(state, 0)  # Початковий XOR з ключем (Раунд 0)

        # Основні раунди шифрування (від 1 до Nr - 1)
        for r in range(1, self.Nr):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, r)

        # Фінальний раунд (без операції MixColumns)
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.Nr)
        return bytes(state)

    def decrypt_block(self, ciphertext):
        """
        Дешифрування одного 16-байтного блоку даних.
        Виконує всі інвертовані кроки у зворотній послідовності.
        """
        state = list(ciphertext)
        # Зняття фінального раундового ключа
        self.add_round_key(state, self.Nr)
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)

        # Зворотний цикл по основних раундах
        for r in range(self.Nr - 1, 0, -1):
            self.add_round_key(state, r)
            self.inv_mix_columns(state)
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)

        # Зняття найпершого початкового ключа (Раунд 0)
        self.add_round_key(state, 0)
        return bytes(state)