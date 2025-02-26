# -*- coding: utf-8 -*-

def gcd(n, m):
    """计算最大公约数"""
    if n < m:
        n, m = m, n
    while m != 0:
        r = n % m
        n = m
        m = r
    return n


def mod_inverse(a, m):
    """计算 a 在模 m 下的乘法逆元"""
    for b in range(1, m):
        if (a * b) % m == 1:
            return b
    return None


def affine_decrypt(ciphertext, a_inv, b, char_map, modulus=28):
    """仿射密码解密：d_k(c) = a⁻¹(c - b) mod 28"""
    plaintext = ""
    for ch in ciphertext:
        if ch in char_map:
            c = char_map[ch]
            m = (a_inv * (c - b)) % modulus
            for char, idx in char_map.items():
                if idx == m:
                    plaintext += char
                    break
        else:
            plaintext += ch
    return plaintext


def score_plaintext(plaintext, meaningful_phrases, ciphertext_len):
    """为明文打分"""
    score = 0
    matched_chars = set()  # 记录已匹配的字符位置，避免重复计分

    # 检查短语匹配
    for phrase in meaningful_phrases:
        if phrase in plaintext:
            start_idx = plaintext.index(phrase)
            phrase_len = len(phrase)
            # 避免重复计分
            if not any(i in matched_chars for i in range(start_idx, start_idx + phrase_len)):
                score += 5  # 基础分
                score += (phrase_len / ciphertext_len) * 10  # 长度占比分
                for i in range(start_idx, start_idx + phrase_len):
                    matched_chars.add(i)
                # 如果短语是完整明文，加分
                if plaintext == phrase:
                    score += 20

    # 长度匹配加分
    if len(plaintext) == ciphertext_len:
        score += 10

    return score


def attack_affine(ciphertext):
    """攻击仿射密码，输出前 10 个有意义的解"""
    # 定义字符集 Z 和映射表
    Z = "计算机学院网络工程信息安全，我们热爱中华人民共和国。大家"
    char_map = {ch: i for i, ch in enumerate(Z)}
    modulus = 28

    # 定义有意义的短语词典
    meaningful_phrases = [
        "计算机学院", "网络工程", "信息安全",
        "我们", "热爱", "中华人民共和国", "大家"
    ]

    print("开始分析仿射密码...")
    print(f"密文: {ciphertext}")
    print("前 10 个有意义的密钥 (a, b) 和明文如下:\n")

    candidates = []  # 存储所有候选解
    ciphertext_len = len(ciphertext)  # 密文长度为 7

    # 遍历所有可能的 a
    for a in range(2, modulus):
        if gcd(a, modulus) == 1:
            a_inv = mod_inverse(a, modulus)
            if a_inv is None:
                continue

            # 遍历所有可能的 b
            for b in range(0, modulus):
                plaintext = affine_decrypt(ciphertext, a_inv, b, char_map, modulus)
                if all(ch in Z for ch in plaintext):
                    score = score_plaintext(plaintext, meaningful_phrases, ciphertext_len)
                    if score > 0:  # 只保留有意义的解
                        candidates.append((score, a, b, plaintext))

    # 按分数从高到低排序
    candidates.sort(reverse=True)

    # 输出前 10 个
    for i, (score, a, b, plaintext) in enumerate(candidates[:10], 1):
        print(f"排名 {i}:")
        print(f"密钥: (a={a}, b={b})")
        print(f"明文: {plaintext}")
        print(f"分数: {score:.2f}")
        print("-" * 50)

    if not candidates:
        print("未找到有意义的明文解！")


def main():
    """主函数，提供友好界面"""
    print("欢迎使用仿射密码攻击程序")
    print("=" * 50)

    # 给定密文
    ciphertext = "和院程安我爱计"
    attack_affine(ciphertext)

    print("\n分析完成！以上为前 10 个有意义的明文和密钥。")


if __name__ == "__main__":
    main()