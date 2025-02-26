import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA


# ------------------------生成密钥对------------------------
def create_rsa_pair(is_save=False):
    '''
    创建rsa公钥私钥对
    :param is_save: default:False
    :return: public_key（十进制）, private_key（十进制）
    '''
    f = RSA.generate(2048)
    private_key_bytes = f.exportKey("PEM")  # 生成私钥（PEM 格式字节）
    public_key_bytes = f.publickey().exportKey("PEM")  # 生成公钥（PEM 格式字节）

    # 将字节转为十进制整数
    private_key = int.from_bytes(private_key_bytes, byteorder='big')
    public_key = int.from_bytes(public_key_bytes, byteorder='big')

    if is_save:
        # 保存为十进制字符串
        with open("crypto_private_key.txt", "w") as f:
            f.write(str(private_key))
        with open("crypto_public_key.txt", "w") as f:
            f.write(str(public_key))

    return public_key, private_key, len(public_key_bytes), len(private_key_bytes)


def read_public_key(file_path="crypto_public_key.txt") -> int:
    with open(file_path, "r") as x:
        public_key = int(x.read())  # 读取十进制字符串并转为整数
        return public_key


def read_private_key(file_path="crypto_private_key.txt") -> int:
    with open(file_path, "r") as x:
        private_key = int(x.read())  # 读取十进制字符串并转为整数
        return private_key


# ------------------------加密------------------------
def encryption(text: str, public_key: int, public_key_length: int):
    # 字符串转为字节
    text = text.encode('utf-8')
    # 将十进制公钥转换回字节
    public_key_bytes = public_key.to_bytes(public_key_length, byteorder='big')
    # 构建公钥对象
    cipher_public = PKCS1_v1_5.new(RSA.importKey(public_key_bytes))
    # 加密（bytes）
    text_encrypted = cipher_public.encrypt(text)
    # 转为十进制
    text_encrypted_decimal = int.from_bytes(text_encrypted, byteorder='big')

    return text_encrypted_decimal, len(text_encrypted)


# ------------------------解密------------------------
def decryption(text_encrypted_decimal: int, private_key: int, private_key_length: int, encrypted_length: int):
    # 将十进制密文转换回字节
    text_encrypted = text_encrypted_decimal.to_bytes(encrypted_length, byteorder='big')
    # 将十进制私钥转换回字节
    private_key_bytes = private_key.to_bytes(private_key_length, byteorder='big')
    # 构建私钥对象
    cipher_private = PKCS1_v1_5.new(RSA.importKey(private_key_bytes))
    # 解密（bytes）
    text_decrypted = cipher_private.decrypt(text_encrypted, Random.new().read)
    # 解码为字符串
    text_decrypted = text_decrypted.decode('utf-8')
    return text_decrypted


if __name__ == '__main__':
    # 生成密钥对
    public_key, private_key, pub_len, priv_len = create_rsa_pair(is_save=False)

    print("公钥（十进制）：", public_key)
    print("私钥（十进制）：", private_key)

    # 加密
    text = 'chenfan'
    text_encrypted_decimal, enc_len = encryption(text, public_key, pub_len)
    print('密文（十进制）：', text_encrypted_decimal)

    # 解密
    text_decrypted = decryption(text_encrypted_decimal, private_key, priv_len, enc_len)
    print('明文：', text_decrypted)