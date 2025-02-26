from random import randint
import sympy
import sys

sys.setrecursionlimit(10000)


def fastExpMod(a, e, m):
    a = a % m
    res = 1
    while e != 0:
        if e & 1:
            res = (res * a) % m
        e >>= 1
        a = (a * a) % m
    return res


def primitive_element(p, q):
    while True:
        g = randint(2, p - 2)
        if fastExpMod(g, 2, p) != 1 and fastExpMod(g, q, p) != 1:
            return g


def e_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = e_gcd(b, a % b)
    return g, y, x - a // b * y


def encrypt(p, g, y, m):
    while True:
        k = randint(2, p - 2)
        if e_gcd(k, p - 1)[0]:
            break
    c1 = fastExpMod(g, k, p)
    c2 = (m * fastExpMod(y, k, p)) % p
    return c1, c2


def decrypt(c1, c2, p, a):
    v = fastExpMod(c1, a, p)
    v_1 = e_gcd(v, p)[1]
    m_d = c2 * v_1 % p
    return m_d


def main():
    m = int(open("F:\Desktop\密码学课设\ELGamalmingwen").readline())
    while True:
        q = sympy.randprime(10 ** 149, 10 ** 150 / 2 - 1)
        if sympy.isprime(q):
            p = 2 * q + 1
            if len(str(p)) == 150 and sympy.isprime(p):
                break
    g = primitive_element(p, q)
    a = randint(2, p - 2)
    y = fastExpMod(g, a, p)
    c1, c2 = encrypt(p, g, y, m)
    m_d = decrypt(c1, c2, p, a)

    if m == m_d:
        print("解密结果与明文相同！解密正确！")
    else:
        print("解密结果与明文不同！解密不正确！")
    return m, p, g, y, c1, c2, m_d


if __name__ == '__main__':
    print("m = %d\nALice的公钥：\np = %d\ng = %d\ny = %d\n密文(C1, C2) = (%d,\n%d)\n明文m = %d"
          % main())
