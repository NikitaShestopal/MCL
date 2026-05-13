import math

def get_prime_factors(n):
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.add(d)
            while temp % d == 0:
                temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    return factors

def find_generator(p):
    q = p - 1
    factors = get_prime_factors(q)

    for a in range(2, p):
        is_generator = True
        for factor in factors:
            if pow(a, q // factor, p) == 1:
                is_generator = False
                break
        if is_generator:
            return a
    return None

def bsgs(a, h, p):
    m = math.ceil(math.sqrt(p - 1))

    table = {}
    for j in range(m):
        table[pow(a, j, p)] = j

    a_inv_m = pow(a, -m, p)

    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * a_inv_m) % p

    return None