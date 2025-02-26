import random


class BigIntegerCrypto:
    def __init__(self):
        pass

    # 模加
    def mod_add(self, a, b, n):
        return (a + b) % n

    # 模减
    def mod_sub(self, a, b, n):
        return (a - b) % n

    # 模乘
    def mod_mul(self, a, b, n):
        return (a * b) % n

    # 模整除
    def mod_div(self, a, b, n):
        # 为了实现模除，需要计算乘法逆
        inv = self.mod_inverse(b, n)
        if inv is None:
            return None
        return self.mod_mul(a, inv, n)

    # 模取余
    def mod_rem(self, a, n):
        return a % n

    # 幂模算法（平方-乘法）
    def mod_pow(self, base, exponent, modulus):
        if modulus == 1:
            return 0
        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent & 1:
                result = (result * base) % modulus
            base = (base * base) % modulus
            exponent >>= 1
        return result

    # 欧几里得算法求GCD
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    # 扩展欧几里得算法求乘法逆
    def mod_inverse(self, a, m):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            return None  # 逆元不存在
        return (x % m + m) % m

    # Miller-Rabin素性测试
    def miller_rabin_test(self, n, k=5):
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        # 写成 n-1 = 2^s * m 的形式
        s = 0
        m = n - 1
        while m % 2 == 0:
            s += 1
            m //= 2

        # 进行k次测试
        for _ in range(k):
            b = random.randrange(2, n - 1)
            x = self.mod_pow(b, m, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(s - 1):
                x = self.mod_pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    # 生成大伪素数
    def generate_prime(self, bits):
        while True:
            # 生成随机奇数
            n = random.randrange(1 << (bits - 1), 1 << bits) | 1
            if self.miller_rabin_test(n, k=5):
                return n


# 测试代码
def test_crypto():
    crypto = BigIntegerCrypto()

    # 测试参数
    a = 7
    b = 5
    n = 13

    print(f"模加: {crypto.mod_add(a, b, n)}")
    print(f"模减: {crypto.mod_sub(a, b, n)}")
    print(f"模乘: {crypto.mod_mul(a, b, n)}")
    print(f"模除: {crypto.mod_div(a, b, n)}")
    print(f"模取余: {crypto.mod_rem(a, n)}")
    print(f"幂模: {crypto.mod_pow(a, 3, n)}")
    print(f"GCD: {crypto.gcd(a, b)}")
    print(f"乘法逆: {crypto.mod_inverse(b, n)}")

    # 生成512位伪素数
    prime = crypto.generate_prime(512)
    print(f"生成的1024位伪素数: {prime}")
    print(f"通过Miller-Rabin测试: {crypto.miller_rabin_test(prime)}")


if __name__ == "__main__":
    test_crypto()