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
        self.y = pow(self.a, self.x, self.p)  # 公钥 y = a^x mod p（修正）
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
        print(f"调试: left = {left}, right = {right}")  # 添加调试信息
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


def main():
    print("欢迎使用 Schnorr 身份识别协议程序")
    print("=" * 50)

    ca = CertificateAuthority(ca_name="MyTrustedCA")
    print("CA 已创建，公钥如下:")
    print(ca.ca_public_key.exportKey("PEM").decode('utf-8'))

    p, q, a = generate_parameters(bits=2048, q_bits=256)
    t = 80

    schnorr_identification(p, q, a, t, ca)


if __name__ == "__main__":
    main()