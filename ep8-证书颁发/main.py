# -*- coding: utf-8 -*-
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import datetime
import json
import os
import random
import time


class CertificateAuthority:
    """证书颁发机构 (CA)"""

    def __init__(self, ca_name="MyCA", key_size=2048):
        self.ca_name = ca_name
        self.key_size = key_size

        # 检查是否已有 CA 密钥文件
        if os.path.exists("ca_private_key.pem") and os.path.exists("ca_public_key.pem"):
            with open("ca_private_key.pem", "rb") as f:
                self.ca_key = RSA.import_key(f.read())
            with open("ca_public_key.pem", "rb") as f:
                self.ca_public_key = RSA.import_key(f.read())
        else:
            # 生成 CA 的 RSA 密钥对并保存
            self.ca_key = RSA.generate(key_size)
            self.ca_public_key = self.ca_key.publickey()
            with open("ca_private_key.pem", "wb") as f:
                f.write(self.ca_key.exportKey("PEM"))
            with open("ca_public_key.pem", "wb") as f:
                f.write(self.ca_public_key.exportKey("PEM"))

    def generate_key_pair(self):
        """为可信实体生成 RSA 公钥和私钥"""
        entity_key = RSA.generate(self.key_size)
        entity_public_key = entity_key.publickey()
        return entity_key, entity_public_key

    def generate_serial_number(self):
        """生成唯一序列号（基于时间戳和随机数）"""
        timestamp = int(time.time() * 1000)  # 毫秒级时间戳
        random_part = random.randint(0, 9999)  # 4 位随机数
        return f"{timestamp}{random_part:04d}"

    def issue_certificate(self, entity_name: str, validity_days=365):
        """为可信实体颁发证书"""
        # 为实体生成密钥对
        entity_private_key, entity_public_key = self.generate_key_pair()

        # 构造证书内容（扩展版 X.509）
        certificate = {
            "version": "v3",  # X.509 v3
            "serial_number": self.generate_serial_number(),
            "issuer": {
                "CN": self.ca_name,
                "O": "Trusted Organization",
                "C": "CN"
            },
            "subject": {
                "CN": entity_name,
                "O": "Entity Organization",
                "C": "CN"
            },
            "public_key": entity_public_key.exportKey("PEM").decode('utf-8'),
            "validity": {
                "not_before": datetime.datetime.utcnow().isoformat(),
                "not_after": (datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)).isoformat()
            },
            "extensions": {
                "keyUsage": "digitalSignature, keyEncipherment",
                "basicConstraints": "CA:FALSE"
            },
            "signature_algorithm": "RSA-SHA256"
        }

        # 将证书内容转为字符串并计算哈希
        cert_content = json.dumps(certificate, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_content)

        # CA 用私钥签名
        signature = pkcs1_15.new(self.ca_key).sign(cert_hash)
        certificate["signature"] = signature.hex()

        # 保存证书为 PEM 文件
        cert_pem = self._to_pem_format(certificate)
        cert_filename = f"cert_{entity_name}_{certificate['serial_number']}.pem"
        with open(cert_filename, "w") as f:
            f.write(cert_pem)
        print(f"证书已保存为: {cert_filename}")

        # 保存实体私钥
        priv_filename = f"private_{entity_name}_{certificate['serial_number']}.pem"
        with open(priv_filename, "w") as f:
            f.write(entity_private_key.exportKey("PEM").decode('utf-8'))
        print(f"私钥已保存为: {priv_filename}")

        return certificate, entity_private_key

    def _to_pem_format(self, certificate: dict) -> str:
        """将证书转换为 PEM 格式"""
        cert_content = json.dumps(certificate, sort_keys=True, ensure_ascii=False)
        pem = "-----BEGIN CERTIFICATE-----\n"
        pem += hashlib.sha256(cert_content.encode('utf-8')).hexdigest() + "\n"  # 简化的编码
        pem += f"Serial Number: {certificate['serial_number']}\n"
        pem += f"Issuer: CN={certificate['issuer']['CN']}\n"
        pem += f"Subject: CN={certificate['subject']['CN']}\n"
        pem += f"Public Key:\n{certificate['public_key']}\n"
        pem += f"Not Before: {certificate['validity']['not_before']}\n"
        pem += f"Not After: {certificate['validity']['not_after']}\n"
        pem += f"Signature: {certificate['signature']}\n"
        pem += "-----END CERTIFICATE-----"
        return pem

    def verify_certificate(self, certificate: dict):
        """验证证书的完整性和有效性"""
        cert_copy = certificate.copy()
        signature_hex = cert_copy.pop("signature")
        signature = bytes.fromhex(signature_hex)

        cert_content = json.dumps(cert_copy, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_content)

        try:
            pkcs1_15.new(self.ca_public_key).verify(cert_hash, signature)
            now = datetime.datetime.utcnow()
            not_before = datetime.datetime.fromisoformat(cert_copy["validity"]["not_before"])
            not_after = datetime.datetime.fromisoformat(cert_copy["validity"]["not_after"])
            if not_before <= now <= not_after:
                print("证书验证通过！")
                return True
            else:
                print("证书已过期或尚未生效！")
                return False
        except (ValueError, TypeError):
            print("证书签名验证失败！")
            return False

    def batch_issue_certificates(self, entity_names: list, validity_days=365):
        """批量颁发证书"""
        certificates = {}
        for entity_name in entity_names:
            print(f"\n为 {entity_name} 颁发证书...")
            cert, priv_key = self.issue_certificate(entity_name, validity_days)
            certificates[entity_name] = (cert, priv_key)
        return certificates


def main():
    """主函数，演示证书颁发和验证"""
    print("欢迎使用证书颁发程序（基于 X.509 和 RSA）")
    print("=" * 50)

    # 创建 CA
    ca = CertificateAuthority(ca_name="MyTrustedCA")
    print("CA 已创建，公钥如下:")
    print(ca.ca_public_key.exportKey("PEM").decode('utf-8'))

    # 用户选择操作
    print("\n请选择操作：")
    print("1: 为单个实体颁发证书")
    print("2: 批量颁发证书")
    choice = input("输入选择 (1 或 2): ")

    if choice == "1":
        entity_name = input("请输入实体名称 (如 Alice): ") or "Alice"
        print(f"\n为 {entity_name} 颁发证书...")
        certificate, entity_private_key = ca.issue_certificate(entity_name)

        # 输出证书详情
        print("\n生成的证书:")
        print(json.dumps(certificate, indent=2, ensure_ascii=False))

        # 验证证书
        print("\n验证证书...")
        ca.verify_certificate(certificate)

        # 篡改测试
        print("\n模拟篡改证书...")
        tampered_cert = certificate.copy()
        tampered_cert["subject"]["CN"] = "MaliciousEntity"
        ca.verify_certificate(tampered_cert)

    elif choice == "2":
        entity_names = input("请输入实体名称列表（用逗号分隔，如 Alice,Bob,Charlie）: ").split(",")
        entity_names = [name.strip() for name in entity_names]
        certificates = ca.batch_issue_certificates(entity_names)

        # 输出所有证书并验证
        for entity_name, (cert, _) in certificates.items():
            print(f"\n{entity_name} 的证书:")
            print(json.dumps(cert, indent=2, ensure_ascii=False))
            print(f"验证 {entity_name} 的证书...")
            ca.verify_certificate(cert)

    else:
        print("无效选择！")


if __name__ == "__main__":
    main()