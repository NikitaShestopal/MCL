# avalanche.py
from sha256_core import sha256_custom

def _count_set_bits(n: int) -> int:
    return bin(n).count('1')

def demonstrate_avalanche() -> None:
    print("\n" + "=" * 60)
    print(" Л3.2: ДЕМОНСТРАЦІЯ ЛАВИННОГО ЕФЕКТУ (SHA-256)")
    print("=" * 60)

    # В мене тут Wikipedia https://uk.wikipedia.org/wiki/%D0%9F%D0%B0%D0%BD%D0%B3%D1%80%D0%B0%D0%BC%D0%B0
    pangrams = [
        "Чуєш їх, доцю, га? Кумедна ж ти, прощайся без ґольфів!",
        "Жебракують філософи при ґанку церкви в Гадячі, ще й шатро їхнє п'яне знаємо.",
        "Фабрикуймо гідність, лящім їжею, ґавами з'їжте ціп.",
        "Щурячий бугай із їжаком-харцизом в ґедзевих ярах.",
        "Глянь, щойно з'їдена ящірка, б'ючись, хапає ґудзик.",
        "Юнзе, вмистуй шпиль, ґеґай, хвацько фокусуй, їж щі.",
        "З'їж юшку, випий ґроґ, десь чатує фах і шмельц.",
        "Хвацький юнкор їхав ґрунтом, щоб з'їсти свіжий інжир.",
        "Ґава ґудзик загубила, дзьобала шипшину, їжачок чкурнув.",
        "Щиглик співає, ґава кряче, хитрий лис їсть філе."
    ]

    for i, p in enumerate(pangrams, 1):
        p_bytes = p.encode('utf-8')
        hash1 = sha256_custom(p_bytes)

        # Інвертуємо 1 біт
        mod_bytes = bytearray(p_bytes)
        mod_bytes[0] ^= 1
        hash2 = sha256_custom(mod_bytes)

        # Обчислюємо різницю
        int1 = int.from_bytes(hash1, 'big')
        int2 = int.from_bytes(hash2, 'big')
        diff_bits = _count_set_bits(int1 ^ int2)
        percentage = (diff_bits / 256) * 100

        print(f"[{i:02d}] {p[:35]:<36}... -> Змінено: {diff_bits:>3}/256 бітів ({percentage:.1f}%)")