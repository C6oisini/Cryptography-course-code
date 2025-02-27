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
import time


class CertificateAuthority:
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

    def issue_certificate(self, entity_name: str, public_key: int, p: int, q: int):
        certificate = {
            "serial_number": f"{int(datetime.datetime.utcnow().timestamp() * 1000)}{random.randint(0, 9999):04d}",
            "issuer": self.ca_name,
            "subject": entity_name,
            "schnorr_public_key": str(public_key),
            "parameters": {"p": str(p), "q": str(q)},
            "validity": {
                "not_before": datetime.datetime.utcnow().isoformat(),
                "not_after": (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
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
        print(f"{entity_name} 的证书已保存为: {cert_filename}")
        return certificate

    def _to_pem_format(self, certificate: dict) -> str:
        cert_content = json.dumps(certificate, sort_keys=True, ensure_ascii=False)
        pem = "-----BEGIN CERTIFICATE-----\n"
        pem += hashlib.sha256(cert_content.encode('utf-8')).hexdigest() + "\n"
        pem += f"Serial Number: {certificate['serial_number']}\n"
        pem += f"Issuer: {certificate['issuer']}\n"
        pem += f"Subject: {certificate['subject']}\n"
        pem += f"Schnorr Public Key: {certificate['schnorr_public_key']}\n"
        pem += f"Not Before: {certificate['validity']['not_before']}\n"
        pem += f"Not After: {certificate['validity']['not_after']}\n"
        pem += f"Signature: {certificate['signature']}\n"
        pem += "-----END CERTIFICATE-----"
        return pem

    def verify_certificate(self, certificate: dict):
        cert_copy = certificate.copy()
        signature_hex = cert_copy.pop("signature")
        signature = bytes.fromhex(signature_hex)

        cert_content = json.dumps(cert_copy, sort_keys=True).encode('utf-8')
        cert_hash = SHA256.new(cert_content)

        try:
            pkcs1_15.new(self.ca_public_key).verify(cert_hash, signature)
            return True
        except (ValueError, TypeError) as e:
            print(f"证书验证失败: {e}")
            return False


class SchnorrProver:
    def __init__(self, name: str, p: int, q: int, a: int, ca: CertificateAuthority):
        self.name = name
        self.p = p
        self.q = q
        self.a = a
        self.x = random.randint(1, q - 1)  # 私钥
        self.y = pow(self.a, self.x, self.p)  # 公钥 y = a^x mod p
        self.certificate = ca.issue_certificate(name, self.y, p, q)
        self.r = None
        self.X = None

    def step_1(self):
        self.r = random.randint(1, self.q - 1)
        self.X = pow(self.a, self.r, self.p)
        return self.X, self.certificate

    def step_3(self, e: int):
        s = (self.r + self.x * e) % self.q
        return s


class SchnorrVerifier:
    def __init__(self, name: str, p: int, q: int, a: int, t: int, ca: CertificateAuthority):
        self.name = name
        self.p = p
        self.q = q
        self.a = a
        self.t = t
        self.ca = ca
        self.e = None

    def step_2(self, X: int, certificate: dict):
        if not self.ca.verify_certificate(certificate):
            print(f"{self.name}: 证书验证失败！")
            return None
        self.y = int(certificate["schnorr_public_key"])
        self.e = random.randint(1, 2 ** self.t - 1)
        return self.e

    def step_4(self, X: int, s: int):
        left = pow(self.a, s, self.p)
        right = (X * pow(self.y, self.e, self.p)) % self.p
        print(f"调试: left = {left}, right = {right}")
        return left == right


def generate_parameters(bits=2048, q_bits=256):
    param_file = "schnorr_params.json"
    if os.path.exists(param_file):
        with open(param_file, "r") as f:
            params = json.load(f)
            print("加载已保存的 Schnorr 参数...")
            return int(params["p"]), int(params["q"]), int(params["a"])

    print(f"生成 {bits} 位 Schnorr 参数（q 为 {q_bits} 位）...")
    start_time = time.time()

    q = number.getPrime(q_bits)
    while True:
        k = number.getRandomNBitInteger(bits - q_bits)
        p = k * q + 1
        if number.isPrime(p):
            break

    while True:
        h = random.randint(2, p - 2)
        a = pow(h, (p - 1) // q, p)
        if a != 1 and pow(a, q, p) == 1:
            break

    params = {"p": str(p), "q": str(q), "a": str(a)}
    with open(param_file, "w") as f:
        json.dump(params, f)
    print(f"参数生成完成，耗时: {time.time() - start_time:.2f} 秒，已保存至 {param_file}")
    return p, q, a


def schnorr_identification(p, q, a, t, ca):
    print(f"\n开始 Schnorr 身份识别协议...")

    P = SchnorrProver("Alice", p, q, a, ca)
    V = SchnorrVerifier("Bob", p, q, a, t, ca)

    X, cert = P.step_1()
    print(f"{P.name}: 发送 X = {X} 和证书给 {V.name}")

    e = V.step_2(X, cert)
    if e is None:
        print("身份验证失败！")
        return
    print(f"{V.name}: 发送询问 e = {e} 给 {P.name}")

    s = P.step_3(e)
    print(f"{P.name}: 发送应答 s = {s} 给 {V.name}")

    if V.step_4(X, s):
        print(f"{V.name}: 身份验证通过，相信对方是 {P.name}")
    else:
        print(f"{V.name}: 身份验证失败！")

    print("\n模拟伪造攻击...")
    fake_P = SchnorrProver("Mallory", p, q, a, ca)
    fake_X, fake_cert = fake_P.step_1()
    print(f"Mallory: 发送伪造的 X = {fake_X} 和证书给 {V.name}")
    fake_e = V.step_2(fake_X, fake_cert)
    if fake_e is None:
        print("伪造身份验证失败！")
        return
    print(f"{V.name}: 发送询问 e = {fake_e} 给 Mallory")
    fake_s = random.randint(1, q - 1)  # Mallory 伪造 s
    print(f"Mallory: 发送伪造的 s = {fake_s} 给 {V.name}")
    if V.step_4(fake_X, fake_s):
        print(f"{V.name}: 伪造验证通过（不应发生）！")
    else:
        print(f"{V.name}: 伪造验证失败，成功阻止攻击！")


def interactive_main():
    print("欢迎使用 Schnorr 身份识别协议程序")
    print("=" * 50)

    ca = None
    p, q, a = None, None, None
    t = 80  # 默认挑战位长度

    while True:
        print("\n请选择操作：")
        print("1. 创建或加载证书颁发机构 (CA)")
        print("2. 生成或加载 Schnorr 参数 (p, q, a)")
        print("3. 执行 Schnorr 身份识别协议")
        print("4. 验证已有证书")
        print("5. 退出程序")

        choice = input("输入选项 (1-5): ").strip()

        if choice == "1":
            # 创建或加载 CA
            ca_name = input("请输入 CA 名称 (默认 MyTrustedCA): ").strip() or "MyTrustedCA"
            key_size = input("请输入 RSA 密钥长度 (默认 2048): ").strip()
            key_size = int(key_size) if key_size.isdigit() else 2048
            ca = CertificateAuthority(ca_name=ca_name, key_size=key_size)
            print("CA 已创建或加载，公钥如下:")
            print(ca.ca_public_key.exportKey("PEM").decode('utf-8'))

        elif choice == "2":
            # 生成或加载 Schnorr 参数
            bits = input("请输入 p 的位长度 (默认 2048): ").strip()
            bits = int(bits) if bits.isdigit() else 2048
            q_bits = input("请输入 q 的位长度 (默认 256): ").strip()
            q_bits = int(q_bits) if q_bits.isdigit() else 256
            p, q, a = generate_parameters(bits=bits, q_bits=q_bits)
            print(f"参数已生成或加载: p = {p}, q = {q}, a = {a}")

        elif choice == "3":
            # 执行 Schnorr 协议
            if ca is None:
                print("错误：请先创建 CA (选项 1)")
                continue
            if p is None or q is None or a is None:
                print("错误：请先生成 Schnorr 参数 (选项 2)")
                continue
            custom_t = input("请输入挑战位长度 t (默认 80): ").strip()
            t = int(custom_t) if custom_t.isdigit() else 80
            schnorr_identification(p, q, a, t, ca)

        elif choice == "4":
            # 验证证书
            if ca is None:
                print("错误：请先创建 CA (选项 1)")
                continue
            cert_file = input("请输入证书文件名 (如 cert_Alice.pem): ").strip()
            if not os.path.exists(cert_file):
                print(f"错误：文件 {cert_file} 不存在")
                continue

            print(f"\n开始验证证书: {cert_file}")
            with open(cert_file, "r") as f:
                cert_pem = f.read()

            # 显示证书原始内容
            print("证书内容如下:")
            print(cert_pem)

            # 解析 PEM 格式证书
            try:
                cert_lines = cert_pem.splitlines()
                cert_dict = {}
                signature = None

                print("\n解析证书字段:")
                for line in cert_lines:
                    if line.startswith("-----BEGIN CERTIFICATE-----"):
                        print("找到证书开始标记")
                    elif line.startswith("-----END CERTIFICATE-----"):
                        print("找到证书结束标记")
                    elif line.startswith("Serial Number:"):
                        cert_dict["serial_number"] = line.split(": ", 1)[1]
                        print(f"序列号: {cert_dict['serial_number']}")
                    elif line.startswith("Issuer:"):
                        cert_dict["issuer"] = line.split(": ", 1)[1]
                        print(f"颁发者: {cert_dict['issuer']}")
                    elif line.startswith("Subject:"):
                        cert_dict["subject"] = line.split(": ", 1)[1]
                        print(f"主体: {cert_dict['subject']}")
                    elif line.startswith("Schnorr Public Key:"):
                        cert_dict["schnorr_public_key"] = line.split(": ", 1)[1]
                        print(f"Schnorr 公钥: {cert_dict['schnorr_public_key']}")
                    elif line.startswith("Not Before:"):
                        cert_dict.setdefault("validity", {})["not_before"] = line.split(": ", 1)[1]
                        print(f"有效期开始: {cert_dict['validity']['not_before']}")
                    elif line.startswith("Not After:"):
                        cert_dict.setdefault("validity", {})["not_after"] = line.split(": ", 1)[1]
                        print(f"有效期结束: {cert_dict['validity']['not_after']}")
                    elif line.startswith("Signature:"):
                        signature = line.split(": ", 1)[1]
                        print(f"签名: {signature[:20]}... (长度: {len(signature)})")
                    elif len(line) == 64 and all(c in "0123456789abcdef" for c in line.lower()):
                        print(f"检测到 SHA256 哈希: {line[:20]}...")

                # 添加固定的 signature_algorithm
                cert_dict["signature_algorithm"] = "RSA-SHA256"
                print("添加签名算法: RSA-SHA256")

                # 添加 parameters
                if p is not None and q is not None:
                    cert_dict["parameters"] = {"p": str(p), "q": str(q)}
                    print(f"添加参数: p = {p}, q = {q}")
                else:
                    print("警告：未加载 Schnorr 参数，使用当前环境参数验证可能不准确")

                # 添加签名
                if signature:
                    cert_dict["signature"] = signature
                    print("签名已添加到证书字典")
                else:
                    raise ValueError("证书中缺少签名")

                # 显示重建的证书字典
                print("\n重建的证书字典:")
                print(json.dumps(cert_dict, indent=2, ensure_ascii=False))

                # 验证证书
                print("\n开始验证签名...")
                if ca.verify_certificate(cert_dict):
                    print(f"证书 {cert_file} 验证通过！")
                else:
                    print(f"证书 {cert_file} 验证失败！")
            except Exception as e:
                print(f"解析证书失败: {e}")

        elif choice == "5":
            print("感谢使用，再见！")
            break

        else:
            print("无效选项，请输入 1-5 之间的数字")


if __name__ == "__main__":
    interactive_main()
