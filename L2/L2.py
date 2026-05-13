from analysis import test_avalanche_effect

def main():
    TRIALS = 1000

    for key_len in [16, 24, 32]:
        bits = key_len * 8
        print(f"Тестування AES-{bits}...")
        avg_pt, avg_key = test_avalanche_effect(key_len, trials=TRIALS)
        print(f"  Середня кількість змінених бітів при зміні 1 біта відкритого тексту: {avg_pt:.2f} (з 128)")
        print(f"  Середня кількість змінених бітів при зміні 1 біта ключа: {avg_key:.2f} (з 128)\n")

    print("=== Л2.2: Дослідження лавинного ефекту (Стандартні раунди) ===")
    print(f"Кількість випробувань: {TRIALS}\n")

    print("=== Л2.3: Вплив кількості раундів для AES-128 ===")
    for r in range(1, 15):
        avg_pt, avg_key = test_avalanche_effect(16, trials=TRIALS, rounds_override=r)
        print(f"Раундів {r}: зміна тексту -> {avg_pt:.2f} біт | зміна ключа -> {avg_key:.2f} біт")

if __name__ == "__main__":
    main()