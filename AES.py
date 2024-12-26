from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def create_aes_ecb_cipher(key):
    """创建AES-ECB模式的加密/解密器"""
    return AES.new(key, AES.MODE_ECB)

def create_key(filename):
    """生成随机密钥16字节"""
    aeskey = get_random_bytes(16)
    with open(f'./.tempfile/{filename}_key', 'wb') as f:
        f.write(aeskey)
    return aeskey
def AESencrypt(message, key):
    """使用AES-ECB模式加密消息"""
    cipher = create_aes_ecb_cipher(key)

    if isinstance(message, str):
        message = message.encode('utf-8')
    padded_message = pad(message, AES.block_size)

    # 加密消息
    encrypted_message = cipher.encrypt(padded_message)

    return encrypted_message


def AESdecrypt(encrypted_message_file, key):
    """使用AES-ECB模式解密消息"""
    cipher = create_aes_ecb_cipher(key)
    with open(encrypted_message_file,'rb') as encrypted_me:
        encrypted_message = encrypted_me.read()

    # 解密消息并移除填充
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    decrypted_message = unpad(decrypted_padded_message, AES.block_size)

    # 将字节串转换回字符串（如果原始消息是字符串）
    # try:
    # decrypted_message = decrypted_message.decode('utf-8')
    # print(decrypted_message)
    # except UnicodeDecodeError:
    #     pass  # 如果原始消息不是字符串，则保持为字节串
    with open(encrypted_message_file, 'wb') as f:
        f.write(decrypted_message)

    return decrypted_message


