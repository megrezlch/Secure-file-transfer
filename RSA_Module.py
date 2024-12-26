import rsa
import base64
import hashlib

def generate_rsakey(pubkey_filename='Alice_public.pem', privkey_filename='Alice_private.pem'):
    (pubkey, privkey) = rsa.newkeys(1024)
    pub = pubkey.save_pkcs1(format='PEM').decode()
    with open(f'./.tempfile/{pubkey_filename}', 'w+') as pubfile:
        pubfile.write(pub)
    pri = privkey.save_pkcs1(format='PEM').decode()
    with open(f'./.tempfile/{privkey_filename}', 'w+') as prifile:
        prifile.write(pri)

def RSAencrypt(public_filename,message, messagesite):
    with open(public_filename, 'rb') as publicfile:
        p = publicfile.read()
        pubkey = rsa.PublicKey.load_pkcs1(p, format='PEM')

    if pubkey is None:
        raise ValueError("Public key not loaded.")

    msg_to_encrypt = message

    try:
        crypto_message = rsa.encrypt(msg_to_encrypt, pubkey)
        with open(messagesite, 'wb') as f:
            f.write(crypto_message)
        # return crypto_message
    except Exception as e:
        print(f"Encryption failed: {e}")
        raise

def RSAdecrypt(pem_filename , crypto_message_filename):
    with open(pem_filename, 'rb') as privatefile:
        p = privatefile.read()
        privkey = rsa.PrivateKey.load_pkcs1(p, format='PEM')
    with open(crypto_message_filename, 'rb') as crypto_message_file:
        crypto_message = crypto_message_file.read()

    if privkey is None:
        raise ValueError("Private key not loaded.")

    try:
        decrypted_message = rsa.decrypt(crypto_message, privkey)
        return decrypted_message
    except rsa.pkcs1.DecryptionError:
        print("Decryption failed.")
        raise

def sign_message(message_filename, pem_filename, sig_filename):
    with open(message_filename, 'rb') as message_file:
        message = message_file.read()

    # 计算消息的哈希值
    message_hash = hashlib.sha256(message).digest()  # 获取二进制格式的哈希值
    message_hash_hex = message_hash.hex()  # 将二进制哈希值转换为十六进制字符串表示

    with open(pem_filename, 'rb') as privatefile:
        p = privatefile.read()
        privkey = rsa.PrivateKey.load_pkcs1(p, format='PEM')

    try:
         # 签名消息的哈希值而不是消息本身
        signature = rsa.sign_hash(message_hash, privkey, 'SHA-256')  # 对二进制哈希值进行签名
        signature_base64 = base64.b64encode(signature).decode('utf-8')

        # 写入签名到文件
        with open(sig_filename, 'w+') as sigfile:
            sigfile.write(signature_base64)

        # print("Signing Succeed.")
        # return  message_hash  # 返回签名和消息摘要

    except Exception as e:
        print(f"Signing failed: {e}")
        raise

def verify_signature(message, pem_filename,sig_filename,signature_base64=None):
    with open(pem_filename, 'rb') as publicfile:
        p = publicfile.read()
        pubkey = rsa.PublicKey.load_pkcs1(p, format='PEM')

    if signature_base64 is None:
        with open(sig_filename, 'r') as sigfile:
            signature_base64 = sigfile.read()

    signature = base64.b64decode(signature_base64)
    try:
        rsa.verify(message, signature, pubkey)
        print("Signature is valid.")
        return True
    except rsa.VerificationError:
        print("Signature is invalid.")
        return False
