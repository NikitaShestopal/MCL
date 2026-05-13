import hashlib
from sha256_core import sha256_custom
from avalanche import demonstrate_avalanche
from collisions import find_partial_collisions


def main():
    print("Перевірка кастомної реалізації SHA-256...")
    test_msg = b"hello world"
    custom_hash = sha256_custom(test_msg)
    standard_hash = hashlib.sha256(test_msg).digest()

    assert custom_hash == standard_hash, "Помилка в реалізації SHA-256!"
    print("Перевірка пройдена успішно. Кастомний SHA-256 працює ідентично стандарту!\n")

    demonstrate_avalanche()

    find_partial_collisions()

if __name__ == '__main__':
    main()