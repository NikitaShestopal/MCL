import collections
import matplotlib.pyplot as plt
from utils import ALPHABET, clean_text

def plot_histogram(text, title="Частота літер"):
    text = clean_text(text)
    counter = collections.Counter(text)

    labels = list(ALPHABET)
    values = [counter.get(char, 0) for char in labels]

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values, color='skyblue')
    plt.title(title)
    plt.xlabel('Літери')
    plt.ylabel('Кількість')
    plt.show()