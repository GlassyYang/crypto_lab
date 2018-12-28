from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import json
import datetime


# 生成支付OI的函数
def oi_generate(order):
    """
    根据订单id生成支付oi
    :param order: 订单id
    :return: 支付oi
    """
    hashed = SHA256.new()
    hashed.update(str(order.total).encode('utf-8'))
    hashed.update(str(order.time).encode('utf-8'))
    for book in order.contain.all():
        hashed.update(book.isbn.encode('utf-8'))
    return hashed.hexdigest()


def sign(pub_key, msg_list):
    from Crypto.Signature import PKCS1_v1_5
    sha = SHA256.new()
    for msg in msg_list:
        sha.update(msg.encode())
    s = PKCS1_v1_5.new(pub_key)
    return b64encode(s.sign(sha))


def ident_gen(order_id):
    global key
    sha = SHA256.new(str(order_id).encode())
    ident = {
        'id': order_id,
        'hash': sha.hexdigest()
    }
    print("gen")
    print(order_id)
    print(sha.hexdigest())
    enc = PKCS1_v1_5.new(key)
    temp = b64encode(enc.encrypt(json.dumps(ident).encode())).decode()
    print('generated id is ')
    print(temp)
    return temp


def enc_msg(aes_key, msg):
    """
    使用CBC模式的AES加密消息
    :param aes_key: 密钥，字节流
    :param msg: 消息，须是字符串
    :return: 加密的密文
    """
    enc = AES.new(aes_key, AES.MODE_CBC, aes_key)
    return b64encode(enc.encrypt(pad(msg.encode('utf-8'), AES.block_size)))


def dec_msg(aes_key, msg):
    """
    使用CBC模式的AES解密之前使用enc_msg()加密的消息
    :param aes_key: 密钥
    :param msg: 密文，须是字节类型
    :return: 字符串类型被加密的明文
    """
    aes = AES.new(aes_key, AES.MODE_CBC, aes_key)
    result = unpad(aes.decrypt(b64decode(msg)), AES.block_size)
    return result


def ident_get(cipher):
    """
    从使用ident_gen()生成的密文中获得订单id
    :param cipher: 密文
    :return: 订单id
    """
    global key
    dec = PKCS1_v1_5.new(key)
    ident = json.loads(dec.decrypt(b64decode(cipher), None))
    order_id = ident['id']
    sha = SHA256.new(str(order_id).encode())
    if ident['hash'] != sha.hexdigest():
        return -1
    else:
        return order_id


def hash_msg(msg_list):
    """
    使用sha256哈希算法散列消息列表中的消息
    :param msg_list: 消息列表，须是list类型，而且元素必须是str类型
    :return: 返回被散列的十六进制字符串
    """
    sha = SHA256.new()
    for msg in msg_list:
        sha.update(msg.encode())
    return sha.hexdigest()


def pkc_enc_msg(pub_key, msg):
    """
    使用公钥加密消息
    :param pub_key: 密钥
    :param msg: 消息，须是bytes类型
    :return: 返回字符串类型的密文
    """
    rsaenc = PKCS1_v1_5.new(pub_key)
    return b64encode(rsaenc.encrypt(msg.encode())).decode('utf-8')


def cert_verify(cert):
    print(cert['publickey'])
    from Crypto.Signature import PKCS1_v1_5
    global cert_root
    fail_time = datetime.datetime.strptime(cert["validData"], '%Y-%m-%d')
    now = datetime.datetime.now()
    if now >= fail_time:
        print("The certificate has out of time!")
        return False
    my_hash = SHA256.new()
    ver_str = cert['version']
    ver_str += cert['publickey']
    ver_str += cert["cert_seq"]
    ver_str += cert['DN']
    ver_str += cert['validData']
    ver_str += cert['ca']
    my_hash.update(ver_str.encode('utf-8'))
    ca_key = RSA.import_key(cert_root['publickey'].encode('utf-8'))
    rsa_ver = PKCS1_v1_5.new(ca_key)
    if not rsa_ver.verify(my_hash, b64decode(cert['signature'].encode('utf-8'))):
        print("bank's certificate verify failed!")
        return False
    return True


def verify_double_sign(key, order, sign):
    from Crypto.Signature import PKCS1_v1_5
    sha = SHA256.new(order.order_pi.encode())
    sha.update(order.order_oi.encode())
    pk = RSA.import_key(key)
    rsa_enc = PKCS1_v1_5.new(pk)
    if rsa_enc.verify(sha, sign.encode()):
        return False
    return True

