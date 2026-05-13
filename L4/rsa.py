from primes import get_512bit_prime

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Немає оберненого елемента')
    return x % m

def gen_rsa_keys():
    p = get_512bit_prime()
    q = get_512bit_prime()
    while p == q:
        q = get_512bit_prime()

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    return (e, n), (d, p, q)

def rsa_enc(m, pub):
    e, n = pub
    return pow(m, e, n)

def rsa_dec_crt(c, priv):
    d, p, q = priv

    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)

    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (q_inv * (m1 - m2)) % p
    m = m2 + h * q

    return m