from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as PkcEnc
from Crypto.Signature import PKCS1_v1_5 as PkcSign
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import json
import datetime
import time
from Crypto.Random import get_random_bytes

email_aes_key = ''


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
    sha = SHA256.new()
    for msg in msg_list:
        if isinstance(msg, str):
            msg = msg.encode()
        sha.update(msg)
    s = PkcSign.new(pub_key)
    return b64encode(s.sign(sha)).decode()


def verify(pri_key, msg_list, hashed):
    sha = SHA256.new()
    for msg in msg_list:
        if isinstance(msg, str):
            msg = msg.encode()
        sha.update(msg)
    s = PkcSign.new(pri_key)
    if s.verify(sha, b64decode(hashed)):
        return True
    else:
        return False


def ident_gen(pk_key, order_id):
    sha = SHA256.new(order_id.encode())
    ident = {
        'id': order_id,
        'hash': sha.hexdigest()
    }
    enc = PkcEnc.new(pk_key)
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
    if isinstance(msg, str):
        msg = msg.encode()
    enc = AES.new(aes_key, AES.MODE_CBC, aes_key)
    return b64encode(enc.encrypt(pad(msg, AES.block_size))).decode()


def dec_msg(aes_key, msg):
    """
    使用CBC模式的AES解密之前使用enc_msg()加密的消息
    :param aes_key: 密钥
    :param msg: 密文，须是字节类型
    :return: 字符串类型被加密的明文
    """
    aes = AES.new(aes_key, AES.MODE_CBC, aes_key)
    result = unpad(aes.decrypt(b64decode(msg)), AES.block_size).decode()
    return result


def ident_get(pub_key, cipher):
    """
    从使用ident_gen()生成的密文中获得订单id
    :param pub_key: 公钥
    :param cipher: 密文
    :return: 订单id
    """
    dec = PkcEnc.new(pub_key)
    ident = json.loads(dec.decrypt(b64decode(cipher), None))
    order_id = ident['id']
    sha = SHA256.new(order_id.encode())
    if sha.hexdigest() != ident['hash']:
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


def pub_enc_msg(pub_key, msg):
    """
    使用公钥加密消息
    :param pub_key: 密钥
    :param msg: 消息，须是bytes类型
    :return: 返回字符串类型的密文
    """
    rsaenc = PkcEnc.new(pub_key)
    return b64encode(rsaenc.encrypt(msg)).decode('utf-8')


def cert_verify(cert, root_cert):
    print(cert['publickey'])
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
    ca_key = RSA.import_key(root_cert['publickey'].encode('utf-8'))
    rsa_ver = PkcSign.new(ca_key)
    if not rsa_ver.verify(my_hash, b64decode(cert['signature'].encode('utf-8'))):
        print("bank's certificate verify failed!")
        return False
    return True


def verify_double_sign(key, order, s):
    sha = SHA256.new(order.order_pi.encode())
    sha.update(order.order_oi.encode())
    pk = RSA.import_key(key)
    rsa_enc = PkcSign.new(pk)
    if rsa_enc.verify(sha, s.encode()):
        return False
    return True


def email_token_gen(pub_key, user):
    global email_aes_key
    if email_aes_key == '':
        email_aes_key = get_random_bytes(16)
    fields = {
        'email': user.email,
        'time': str(int(time.time()))
    }
    fields['sign'] = sign(pub_key, [fields['email'], fields['time']])
    return enc_msg(email_aes_key, json.dumps(fields))


def get_email(pub_key, token):
    global email_aes_key
    if email_aes_key == '':
        return None
    fields = dec_msg(email_aes_key, token)
    fields = json.loads(fields)
    if verify(pub_key, [fields['email'], fields['time']], fields['sign']):
        return fields['email']
    now = int(time.time())
    if now - int(fields['time']) > 600:
        return None
