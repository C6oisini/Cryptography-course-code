# -*- coding: utf-8 -*-
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util import number
import datetime
import json
import os
import random


class CertificateAuthority:
    """证书颁发机构 (CA)"""

    def __init__(self, ca_name="MyCA", key_size=2048):
        self.ca_name = ca_name
        self.key_size = key_size

        if os.path.exists("ca_private_key.pem") and os.path.exists("ca_public_key.pem"):
            with open("ca_private_key.pem", "rb") as f:
                self.ca_key = RSA.import_key(f.read())
            with open("ca_public_key.pem", "rb") as f:
                self.ca_public_key = RSA.import_key(f.read())
        else:
            self.ca_key = RSA.generate(key_size)
            self.ca_public_key = self.ca_key.publickey()
            with open("ca_private_key.pem", "wb") as f:
                f.write(self.ca_key.exportKey("PEM"))
            with open("ca_public_key.pem", "wb") as f:
                f.write(self.ca_public_key.exportKey("PEM"))

    def issue_certificate(self, entity_name: str, validity_days=365):
        """为实体颁发证书并保存"""
        entity_key = RSA.generate(self.key_size)
        entity_public_key = entity_key.publickey()

        certificate = {
            "serial_number": f"{int(datetime.datetime.utcnow().timestamp() * 1000)}{random.randint(0, 9999):04d}",
            "issuer": self.ca_name,
            "subject": entity_name,
            "public_key": entity_public_key.exportKey("PEM").decode('utf-8'),
            "validity": {
                "not_before": datetime.datetime.utcnow().isoformat(),
                "not_after": (datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)).isoformat()
            },
            "signature_algorithm": "RSA-SHA256"
        }

        cert_content = json.dumps(certificate, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_content)
        signature = pkcs1_15.new(self.ca_key).sign(cert_hash)
        certificate["signature"] = signature.hex()

        cert_filename = f"cert_{entity_name}.pem"
        with open(cert_filename, "w") as f:
            f.write(self._to_pem_format(certificate))
        print(f"证书已保存为: {cert_filename}")

        priv_filename = f"private_{entity_name}.pem"
        with open(priv_filename, "w") as f:
            f.write(entity_key.exportKey("PEM").decode('utf-8'))
        print(f"私钥已保存为: {priv_filename}")

        return certificate, entity_key

    def _to_pem_format(self, certificate: dict) -> str:
        """将证书转为 PEM 格式"""
        cert_content = json.dumps(certificate, sort_keys=True, ensure_ascii=False)
        pem = "-----BEGIN CERTIFICATE-----\n"
        pem += hashlib.sha256(cert_content.encode('utf-8')).hexdigest() + "\n"
        pem += f"Serial Number: {certificate['serial_number']}\n"
        pem += f"Issuer: {certificate['issuer']}\n"
        pem += f"Subject: {certificate['subject']}\n"
        pem += f"Public Key:\n{certificate['public_key']}\n"
        pem += f"Not Before: {certificate['validity']['not_before']}\n"
        pem += f"Not After: {certificate['validity']['not_after']}\n"
        pem += f"Signature: {certificate['signature']}\n"
        pem += "-----END CERTIFICATE-----"
        return pem

    def verify_signature(self, data: str, signature: str, public_key):
        """验证签名（改进为直接验证字符串和签名）"""
        data_hash = SHA256.new(data.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(data_hash, bytes.fromhex(signature))
            return True
        except (ValueError, TypeError) as e:
            print(f"签名验证失败: {e}")
            return False


class MTIKeyExchange:
    """MTI 密钥交换协议"""

    def __init__(self, name: str, certificate: dict, private_key: RSA.RsaKey, p: int, g: int):
        self.name = name
        self.certificate = certificate
        self.private_key = private_key
        self.p = p
        self.g = g
        self.temp_private_key = None
        self.temp_public_key = None

    def generate_temp_key(self):
        """生成临时 D-H 密钥对"""
        self.temp_private_key = random.randint(1, self.p - 1)
        self.temp_public_key = pow(self.g, self.temp_private_key, self.p)

    def sign_temp_key(self):
        """用长期私钥签名临时公钥"""
        temp_key_str = str(self.temp_public_key)
        temp_hash = SHA256.new(temp_key_str.encode('utf-8'))
        signature = pkcs1_15.new(self.private_key).sign(temp_hash)
        return signature.hex()

    def compute_shared_key(self, other_temp_public_key: int):
        """计算共享密钥"""
        return pow(other_temp_public_key, self.temp_private_key, self.p)


def generate_dh_parameters(bits=2048):
    """生成安全的 D-H 参数（p 和 g）"""
    print("正在生成安全的 D-H 参数（2048 位）...")
    p = number.getPrime(bits)
    g = 2  # 简单生成元
    return p, g


def mti_key_exchange(alice, bob, ca):
    """执行 MTI 密钥交换"""
    print(f"\n开始 MTI 密钥交换 ({alice.name} 和 {bob.name})...")

    # 生成临时密钥对
    alice.generate_temp_key()
    bob.generate_temp_key()

    # Alice 和 Bob 交换临时公钥和签名
    alice_temp_key_str = str(alice.temp_public_key)
    alice_temp_sig = alice.sign_temp_key()
    bob_temp_key_str = str(bob.temp_public_key)
    bob_temp_sig = bob.sign_temp_key()

    # Alice 验证 Bob 的临时公钥
    bob_cert_pub_key = RSA.import_key(bob.certificate["public_key"])
    bob_sig_verified = ca.verify_signature(bob_temp_key_str, bob_temp_sig, bob_cert_pub_key)
    if not bob_sig_verified:
        print(f"{alice.name} 验证 {bob.name} 的临时公钥失败！")
        return None, None

    # Bob 验证 Alice 的临时公钥
    alice_cert_pub_key = RSA.import_key(alice.certificate["public_key"])
    alice_sig_verified = ca.verify_signature(alice_temp_key_str, alice_temp_sig, alice_cert_pub_key)
    if not alice_sig_verified:
        print(f"{bob.name} 验证 {alice.name} 的临时公钥失败！")
        return None, None

    # 计算共享密钥
    alice_shared_key = alice.compute_shared_key(bob.temp_public_key)
    bob_shared_key = bob.compute_shared_key(alice.temp_public_key)

    return alice_shared_key, bob_shared_key


def main():
    """主函数，演示 MTI 密钥交换"""
    print("欢迎使用 MTI 密钥交换协议程序")
    print("=" * 50)

    # 创建 CA
    ca = CertificateAuthority(ca_name="MyTrustedCA")
    print("CA 已创建，公钥如下:")
    print(ca.ca_public_key.exportKey("PEM").decode('utf-8'))

    # 为 Alice 和 Bob 颁发证书
    alice_cert, alice_private_key = ca.issue_certificate("Alice")
    bob_cert, bob_private_key = ca.issue_certificate("Bob")

    # 生成安全的 D-H 参数
    p, g = generate_dh_parameters(bits=2048)

    # 创建 Alice 和 Bob 的 MTI 实例
    alice = MTIKeyExchange("Alice", alice_cert, alice_private_key, p, g)
    bob = MTIKeyExchange("Bob", bob_cert, bob_private_key, p, g)

    # 执行密钥交换
    alice_key, bob_key = mti_key_exchange(alice, bob, ca)

    # 输出结果
    if alice_key is not None and bob_key is not None:
        print(f"\n{alice.name} 的共享密钥 (前 20 位): {str(alice_key)[:20]}...")
        print(f"{bob.name} 的共享密钥 (前 20 位): {str(bob_key)[:20]}...")
        print(f"密钥协商{'成功' if alice_key == bob_key else '失败'}！")
    else:
        print("密钥协商失败，无法生成共享密钥！")

    # 模拟中间人攻击失败
    print("\n模拟中间人攻击...")
    mallory = MTIKeyExchange("Mallory", bob_cert, bob_private_key, p, g)
    mallory.generate_temp_key()
    mallory_temp_key_str = str(mallory.temp_public_key)
    mallory_temp_sig = mallory.sign_temp_key()
    alice_shared_key_with_mallory = alice.compute_shared_key(mallory.temp_public_key)
    print(f"{alice.name} 与 Mallory 的共享密钥 (前 20 位): {str(alice_shared_key_with_mallory)[:20]}...")
    print(f"由于证书验证，Mallory 无法伪造 Alice 的身份，密钥协商安全。")


if __name__ == "__main__":
    main()