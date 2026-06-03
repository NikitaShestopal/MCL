import hashlib
from sha256_core import sha256_custom
from avalanche import demonstrate_avalanche
from collisions import find_partial_collisions


def main():
    print("Перевірка кастомної реалізації SHA-256...")
    test_msg = b"hello world"

    # Обчислення хешу через власну та стандартну бібліотечну реалізацію
    custom_hash = sha256_custom(test_msg)
    standard_hash = hashlib.sha256(test_msg).digest()

    # Верифікація математичної точності розрахунків
    assert custom_hash == standard_hash, "Помилка в реалізації SHA-256!"
    print("Перевірка пройдена успішно. Кастомний SHA-256 працює ідентично стандарту!\n")

    # Л3.2: Запуск демонстрації лавинного ефекту на базі українських панграм
    demonstrate_avalanche()

    # Л3.3: Запуск статистичного тестування часу пошуку часткових колізій
    find_partial_collisions()


if __name__ == '__main__':
    main()