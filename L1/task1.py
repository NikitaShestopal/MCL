import collections
import matplotlib.pyplot as plt
from utils import ALPHABET, clean_text


def plot_histogram(text, title="Частота літер"):
    """
    Будує гістограму частоти появи літер у тексті на основі заданого алфавіту.
    """
    # Попередня обробка тексту (приведення до нижнього регістру, видалення символів)
    text = clean_text(text)

    # Підрахунок кількості входжень кожного символу в тексті
    counter = collections.Counter(text)

    # Формування списку літер алфавіту для осі X
    labels = list(ALPHABET)
    # Отримання значень частот для кожної літери (якщо літери немає в тексті, повертає 0)
    values = [counter.get(char, 0) for char in labels]

    # Налаштування розміру та відображення графіка за допомогою matplotlib
    plt.figure(figsize=(10, 5))
    plt.bar(labels, values, color='skyblue')  # Побудова стовпчикової діаграми
    plt.title(title)  # Заголовок графіка
    plt.xlabel('Літери')  # Підпис осі абсцис
    plt.ylabel('Кількість')  # Підпис осі ординат
    plt.show()  # Відображення вікна з графіком