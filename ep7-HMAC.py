# -*- coding: utf-8 -*-
import hmac
import hashlib


def generate_hmac(key: bytes, message: bytes) -> str:
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()


def verify_hmac(key: bytes, message: bytes, received_hmac: str) -> bool:
    local_hmac = generate_hmac(key, message)
    print(f"接收方计算的 HMAC: {local_hmac}")  # 新增：显示本地计算的 HMAC
    return hmac.compare_digest(local_hmac, received_hmac)


def simulate_transmission(message: str, key: str, tamper=False) -> tuple:
    message_bytes = message.encode('utf-8')
    key_bytes = key.encode('utf-8')
    sent_hmac = generate_hmac(key_bytes, message_bytes)

    if tamper:
        tampered_message = (message + "nb").encode('utf-8')
        print(f"传输中篡改消息为: {tampered_message.decode('utf-8')}")
        return tampered_message, sent_hmac
    return message_bytes, sent_hmac


def main():
    print("欢迎使用信息完整性认证程序（基于 HMAC-SHA256）")
    print("=" * 50)

    message = input("请输入消息: ")
    key = input("请输入密钥: ")

    print("\n--- 模拟正常传输 ---")
    sent_message_bytes, sent_hmac = simulate_transmission(message, key, tamper=False)
    sent_message = sent_message_bytes.decode('utf-8')
    print(f"发送消息: {sent_message}")
    print(f"发送 HMAC: {sent_hmac}")
    is_valid = verify_hmac(key.encode('utf-8'), sent_message_bytes, sent_hmac)
    print(f"完整性验证结果: {'通过' if is_valid else '未通过'}")

    print("\n--- 模拟篡改传输 ---")
    tampered_message_bytes, sent_hmac = simulate_transmission(message, key, tamper=True)
    tampered_message = tampered_message_bytes.decode('utf-8')
    print(f"接收消息: {tampered_message}")
    print(f"发送 HMAC: {sent_hmac}")
    is_valid = verify_hmac(key.encode('utf-8'), tampered_message_bytes, sent_hmac)
    print(f"完整性验证结果: {'通过' if is_valid else '未通过'}")


if __name__ == "__main__":
    main()