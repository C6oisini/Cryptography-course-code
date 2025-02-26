# -*- coding: utf-8 -*-

def LFSR(K, output_length=20):
    """
    线性反馈移位寄存器 (LFSR) 实现
    参数:
        K: 种子密钥，二进制字符串 (如 "1010")
        output_length: 生成的伪随机序列长度，默认为 20
    返回:
        生成的伪随机序列 (字符串形式)
    """
    # 检查输入是否为合法的二进制字符串
    if not all(bit in '01' for bit in K):
        raise ValueError("种子密钥必须是 01 串")
    if len(K) < 2:
        raise ValueError("种子密钥长度至少为 2")

    # 初始化状态 S0
    state = list(K)  # 将字符串转为列表，方便操作
    n = len(state)   # LFSR 的长度

    # 定义反馈多项式
    # 这里使用示例多项式 x^n + x^(n-1) + 1
    # 对于 4 位 LFSR，即 x^4 + x^3 + 1，反馈位为第 3 位和第 0 位（从左到右计数）
    feedback_taps = [n-1, 0]  # 反馈位索引，从 0 开始（最右为 0）

    # 生成伪随机序列
    output = ""
    for _ in range(output_length):
        # 输出最右一位
        output_bit = state[-1]
        output += output_bit

        # 计算反馈值（异或操作）
        feedback = 0
        for tap in feedback_taps:
            feedback ^= int(state[tap])

        # 整体右移
        state.pop()  # 移除最右位
        state.insert(0, str(feedback))  # 在最左位插入反馈值

    return output

# 测试函数
def test_LFSR():
    test_cases = [
        ("1010", 20),  # 4 位种子，生成 20 位序列
        ("11001", 25), # 5 位种子，生成 25 位序列
    ]

    for K, length in test_cases:
        result = LFSR(K, length)
        print(f"种子密钥: {K}")
        print(f"生成的伪随机序列: {result}")
        print(f"长度: {len(result)}\n")

if __name__ == "__main__":
    # 运行测试
    # test_LFSR()

    # 用户输入测试
    seed = input("请输入种子密钥 (二进制串，如 1010): ")
    length = int(input("请输入生成序列的长度: "))
    sequence = LFSR(seed, length)
    print(f"种子密钥: {seed}")
    print(f"生成的伪随机序列: {sequence}")