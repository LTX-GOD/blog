---
title: 2025江苏省密码行业职业技能竞赛
published: 2025-11-04
pubDate: 2025-11-04
description: 江苏省密码行业职业技能竞赛
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

不让外省的玩，赛后拿到题复现一下

## 题目

### 解码第一步！签到礼

> ZmxhZ3tXMzFDMG00X1QwX0pTU01NSFlaWUpOSlN9

一把梭

```bash
echo "ZmxhZ3tXMzFDMG00X1QwX0pTU01NSFlaWUpOSlN9" | base64 -d
flag{W31C0m4_T0_JSSMMHYZYJNJS}
```

### 找不到的 p 和 q

task.py

```python
from Crypto.Util.number import bytes_to_long,inverse,getPrime
from flag import flag

m = bytes_to_long(flag)

p = getPrime(1024)
q = getPrime(1024)
n = p*q
print(n)
e = 65537

c = pow(m,e,n)

pq = p*(q-1)
qp = q*(p-1)

print("c=",c)
print("n=",n)
print("pq=",pq)
print("qp=",qp)
```

很简单的小数学题，`phi=pq*qp//n`，那么就出来了

exp.py

```python
from Crypto.Util.number import *

c=
n=
pq=
qp=

print(long_to_bytes(pow(c,inverse(65537,pq*qp//n),n)))
```

### 紧急援助

图片是个魔丸真无敌了孩子

`stegsolve`启动，然后解密压缩包得到信息

```txt
昨天截获消息
MSG1(HEX)：
5e3ccd56f6537deb95da
MAC１(HEX)：
3383c6d4ddf4838a096a580487cd7980

今天截获的消息
MSG２(HEX)：
683a49bc0202562cd3bbfa9f6c618fa36282a423fcbd01a62f9fd99fe76a8ab8
MAC２(HEX)：
3c2cbadfe280d5535bb60f6d5df922fd

利用以上2组已知数据，帮助王特工伪造一个能够通过完整性验证的新消息，替换王特工今天截获的消息，即替换MSG2，使得替换信息计算出的MAC值仍然为MAC2。（注：伪造的替换信息须满足以下格式：1、字节串格式下长度须为48字节；2、最后16字节应与MSG2的最后16字节一致。）
```

先填充一下 msg1`5e3ccd56f6537deb95da000000000000`

MSG2 拆成两块`683a49bc0202562cd3bbfa9f6c618fa3`以及`6282a423fcbd01a62f9fd99fe76a8ab8`

第一块和 mac1 给 xor 一下，得到`5bb98f68dff6d5a6dad1a29bebacf6236`，连一起拿到`5e3ccd56f6537deb95da0000000000005bb98f68dff6d5a6dad1a29bebacf6236282a423fcbd01a62f9fd99fe76a8ab8`

### special dh

task.py

```python
p = 65537
g = 5
公开常数：c1 = 19，c2 = 47，c3 = 101
Alice 的公钥：A = 0x7F2
Bob 的公钥：B = 0x2A3D

specialDH 共享密钥计算代码如下：
def modinv(x, p):
        return pow(x, p-2, p)

def compute_special_dh_key(B, a, p, c1, c2, c3):
    part1 = (pow(B, a, p) * c1) % p
    part2 = (part1 + c2) % p
    inv_c3 = modinv(c3, p)
    return (part2 * inv_c3) % p
```

ab 的私钥一看就很小，直接爆破就行

exp.py

```python
import math

p=65537
g=5
c1=19
c2=47
c3=101
A=int("7F2",16);B=int("2A3D",16)
def modinv(x,p): return pow(x,p-2,p)
def bsgs(g,h,p):
    m=int(math.ceil((p-1)**0.5))
    table={}
    e=1
    for j in range(m):
        if e not in table: table[e]=j
        e=e*g%p
    g_m_inv=pow(g,m*(p-2),p)
    gamma=h
    for i in range(m+1):
        if gamma in table:
            a=i*m+table[gamma]
            if pow(g,a,p)==h: return a
        gamma=gamma*g_m_inv%p
    return None
a=bsgs(g,A,p)
part1=(pow(B,a,p)*c1)%p
part2=(part1+c2)%p
key=(part2*modinv(c3,p))%p
print(key)
print(hex(key))
```

### 异或谜题

task.py

```python
from flag import flag

def encrypt(x, y):
    key = 'abc'
    result = ''
    for i in range(len(x)):
        result += chr(ord(x[i]) ^ ord(y[i]) ^ ord(key[i % 3]))
    return result

x = flag
y = flag[1:] + flag[0]

enc = open('flag.enc', 'wb')
enc.write(encrypt(x, y))
enc.close()
```

密文：6b6f657d41747c6f757b6e7a727963761a3f7a

加密是循环的，最后一个依赖第一个，第一个是`f`，开爆

exp.py

```python
enc_hex = "6b6f657d41747c6f757b6e7a727963761a3f7a"
c = list(bytes.fromhex(enc_hex))
key = [ord('a'), ord('b'), ord('c')]
n = len(c)

for start in range(32,127):
    f = [0]*n
    f[0] = start
    for i in range(n-1):
        f[i+1] = f[i] ^ c[i] ^ key[i%3]
    # 验证循环一致性
    if f[0] == (f[-1] ^ c[-1] ^ key[(n-1)%3]):
        flag = ''.join(chr(x) for x in f)
        if flag.startswith("flag{"):
            print(flag)
            break
```

### 以假乱真之术

task.txt

```txt
已知的公钥、消息摘要及签名值如下：
公钥（HEX）：
消息摘要（HEX）：84ffb82e
签名值（HEX）：

给定的新消息摘要（HEX）：abffcdef
```

task.py

```python
from hashlib import sha256

# 字节串分组函数
def to_byte_blocks(hex_str):
    # 确保十六进制字符串长度是64的倍数
    if len(hex_str) % 64 != 0:
        raise ValueError("十六进制字符串长度必须是64的倍数")
    # 字节串分组
    byte_blocks=[bytes.fromhex(hex_str[i:i + 64]) for i in range(0, len(hex_str), 64)]
    return byte_blocks

# 转化消息摘要函数
def digest_transform(digest,base):
    # 从字节转换为整数
    digest_int = int.from_bytes(digest, "big")
    # 将消息摘要特殊转换
    message_tobe_signed = []
    if digest_int == 0:
        message_tobe_signed = [0]  # 如果消息摘要为空，直接返回 0
    while digest_int:
        message_tobe_signed.append(int(digest_int % base))  # 取在十六进制下的个位，即余数
        digest_int //= base  # 对数字进行整除，处理下一位
    return message_tobe_signed[::-1]  # 逆序，使数值在列表中的位置与其代表的十六进制数位对应

# 公钥获取函数
def get_pubkey(digest,signature_list,base=16):
    # 将消息摘要特殊转换
    message_tobe_verified = digest_transform(digest,base)
    # 计算获取公钥分组
    pubkey_verify = []
    for index, value in enumerate(message_tobe_verified):
        sig_part = signature_list[index]
        # 反复SHA256杂凑运算后的杂凑值
        for i in range(value, base - 1):
            sig_part = sha256(sig_part).digest()
        pubkey_verify.append(sig_part)
    return pubkey_verify

# 签名验证函数
def verify(pubkey, digest, signature):
    # 调整参数格式
    digest_byte = bytes.fromhex(digest)
    signature_block = to_byte_blocks(signature)
    pubkey_block = to_byte_blocks(pubkey)
    # 验证签名
    pubkey_verify = get_pubkey(digest_byte, signature_block)
    if pubkey_verify == pubkey_block:
        return "True" # 验证成功
    else:
        return "False"

#测试公钥
pubkey = ""
#测试消息摘要
digest = "84ffb82e"
#测试签名值
signature = ""
# 验证签名
valid = verify(pubkey,digest,signature)
print(valid)

```

好像是今年熵密杯的题。

我们已知一个签名，要伪造另一个签名，就可以把对应块再多哈希若干次。

exp.py

```python
from hashlib import sha256
pubkey="5057432973dc856a7a00272d83ea1c14de52b5eb3ba8b70b373db8204eb2f902450e38dbade5e9b8c2c3f8258edc4b7e8101e94ac86e4b3cba92ddf3d5de2a2b454c067a995060d1664669b45974b15b3423cec342024fe9ccd4936670ec3abaae4f6b97279bd8eb26463a8cb3112e6dcbf6301e4142b9cdc4adfb644c7b114af4f0cf8f80e22c3975ba477dc4769c3ef67ffdf2090735d81d07bc2e6235af1ee41ef332215422d31208c2bc2163d6690bd32f4926b2858ca41c12eec88c0a300571901a3f674288e4a623220fb6b70e558d9819d2f23da6d897278f4056c346d7f729f5f70805ad4e5bd25cfa502c0625ac02185e014cf36db4ebcdb3ed1a38"
sig="25d5a0e650d683506bfe9d2eca6a3a99b547a4b99398622f6666ce10131e971b6bd36841c9074fe9b4de2900ebe3fadb3202a173be486da6cf8f3d8c699c95c3454c067a995060d1664669b45974b15b3423cec342024fe9ccd4936670ec3abaae4f6b97279bd8eb26463a8cb3112e6dcbf6301e4142b9cdc4adfb644c7b114a4966398a789b56bdb09ea195925e7e8cde372305d244604c48db08f08a6e8a38951030deb25a7aaf1c07152a302ebc07d5d0893b5e9a5953f3b8500179d138b9aa90c0aaacea0c23d22a25a86c0b747c561b480175b548fcb1f4ad1153413bc74d9c049d43ffe18ceee31e5be8bdb9968103ef32fb4054a4a23c400bbfe0d89f"
def to_blocks(h):return [bytes.fromhex(h[i:i+64]) for i in range(0,len(h),64)]
old="84ffb82e"
new="abffcdef"
a=[int(x,16) for x in old]
b=[int(x,16) for x in new]
sig_blocks=to_blocks(sig)
res=[]
for s,x,y in zip(sig_blocks,a,b):
    t=s
    for _ in range(y-x):t=sha256(t).digest()
    res.append(t.hex())
print(''.join(res))
```

### 熊猫特工的千层饼

task.txt

```txt
VGhlIGZsYWcgaXMgYmFzZTY0IGVuY29kZWQuIEJ1dCBkb24ndCBzdG9wIHRoZXJlLiBUaGlzIGlzIG9ubHkgdGhlIGZpcnN0IGxheWVyLiBGbGFnOiA2ZDc1NmM3NDY5NmM2MTc5NjU3MjVmNjU2ZTYzNmY2NDY5NmU2Nw==
```

扔厨子里面一把梭

### Lattice RSA

task.py

```python
from Crypto.Util.number import *
from secret import flag

flag = flag.getflag()
m = bytes_to_long(flag)
d = getPrime(399)

for i in range(4):
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = inverse(d, (p-1)*(q-1))
    c = pow(m, e, n)
    print(f'e{i} =', e)
    print(f'n{i} =', n)
    print(f'c{i} =', c)
```

多个 e 的维纳，打个格就行了，论文直接给的，里面有说。

```python
M = int(pow(n3,0.5))
B = Matrix(ZZ, [ [M, e0,   e1,  e2, e3],
                 [0, -n0,   0,   0,  0],
                 [0, 0,   -n1,   0,  0],
                 [0, 0,   0,   -n2,  0],
                 [0, 0,   0,   0,  -n3]])
```

### 密径寻钥

task1.py

```python
from Crypto.Cipher import AES
import base64
import sys

def pkcs7_pad(data):
    """使用PKCS#7填充方式补足数据长度为AES块大小的倍数"""
    block_size = AES.block_size
    pad_length = block_size - len(data) % block_size
    return data + bytes([pad_length]) * pad_length

def validate_inputs(key1, key2, iv):
    """验证输入的合法性"""
    # 组合密钥（取前16/24/32字节，对应AES-128/192/256）
    combined_key = (key1 + key2).encode('utf-8')
    valid_key_lengths = [16, 24, 32]
    if len(combined_key) not in valid_key_lengths:
        # 截断或填充到最近的有效长度（实际应用中应严格要求长度）
        new_len = min([l for l in valid_key_lengths if l >= len(combined_key)], default=16)
        combined_key = combined_key.ljust(new_len, b'\x00')[:new_len]
        print(f"警告：组合密钥长度不符合标准，已自动调整为{new_len*8}位")

    # 验证IV长度（AES要求IV必须为16字节）
    iv_bytes = iv.encode('utf-8')
    if len(iv_bytes) != 16:
        raise ValueError("IV必须为16字节长度的字符串")

    return combined_key, iv_bytes

def aes_cbc_encrypt(flag, key1, key2, iv):
    """
    使用AES-CBC模式加密flag
    :param flag: 明文flag（字符串）
    :param key1: 密钥部分1（字符串）
    :param key2: 密钥部分2（字符串）
    :param iv: 初始化向量（16字节字符串）
    :return: Base64编码的密文
    """
    try:
        # 验证并处理密钥和IV
        key, iv_bytes = validate_inputs(key1, key2, iv)

        # 处理明文
        plaintext = flag.encode('utf-8')
        padded_plaintext = pkcs7_pad(plaintext)

        # 加密
        cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
        ciphertext = cipher.encrypt(padded_plaintext)

        # 返回Base64编码的密文
        return base64.b64encode(ciphertext).decode('utf-8')

    except Exception as e:
        return f"加密失败：{str(e)}"

if __name__ == "__main__":
    print("=== AES-CBC加密工具 ===")
    print("请输入以下参数（注意：IV必须为16字节）")

    # 获取用户输入
    key1 = input("请输入key1: ").strip()
    key2 = input("请输入key2: ").strip()
    iv = input("请输入IV（16字节）: ").strip()
    flag = input("请输入要加密的flag: ").strip()

    # 执行加密
    result = aes_cbc_encrypt(flag, key1, key2, iv)
    print("\n加密结果（Base64）:")
    print(result)
```

task2.txt

```txt
flag密文：
+YBx43FhqeZ3if4exR7Q1T6oO27doVGFyZjwdauqGWf6NXUl3reMlE72FHxT1U6Z

IV值：
2daeb325d1a426b2
```

task3.py

```python
import libnum
import random
import gmpy2
from secret import key1
#生成随机素数
p=libnum.generate_prime(512)
q=libnum.generate_prime(512)

#字符串转数字
m=libnum.s2n(key1)
n=p*q
phi_n=(p-1)*(q-1)
#计算d
while True:
    nbits=1024
    d = random.getrandbits(nbits // 4)
    if (libnum.gcd(d, phi_n) == 1 and 36 * pow(d, 4) < n):
        break
#计算e
e = libnum.invmod(d,phi_n)
c=pow(m,e,n)
print ("n=",n)
print ("e=",e)
print ("c=",c)
```

task4.txt

```txt
n=
e=
c=
```

task5 是个 png，包括宽高可以拿到 key2 的值，`KEY2=c46fdb7c50c4a891`

前面 e 那么大一看就是维纳，直接求出 key1，key1+key2 就是 key，拿去 aes 解密

```python
import gmpy2
from math import sqrt

def transform(x,y):       #使用辗转相处将分数 x/y 转为连分数的形式
    res=[]
    while y:
        res.append(x//y)
        x,y=y,x%y
    return res

def continued_fraction(sub_res):
    numerator,denominator=1,0
    for i in sub_res[::-1]:      #从sublist的后面往前循环
        denominator,numerator=numerator,i*numerator+denominator
    return denominator,numerator   #得到渐进分数的分母和分子，并返回


#求解每个渐进分数
def sub_fraction(x,y):
    res=transform(x,y)
    res=list(map(continued_fraction,(res[0:i] for i in range(1,len(res)))))  #将连分数的结果逐一截取以求渐进分数
    return res

#以上是获得e/n的连分数



def wienerAttack(e,n):
    for (x,y) in sub_fraction(e,n):  #用一个for循环来注意试探e/n的连续函数的渐进分数，直到找到一个满足条件的渐进分数
        k = y
        d = x

        if pow(3,e*d,n)==3:
            print("[+]")
            print(d.bit_length())
            print(k,d)

            return d


n=
e=

d=wienerAttack(e,n)

c=
from Crypto.Util.number import *
print(long_to_bytes(pow(c,d,n)))

from base64 import *
enc = b64decode(b'+YBx43FhqeZ3if4exR7Q1T6oO27doVGFyZjwdauqGWf6NXUl3reMlE72FHxT1U6Z')

from Crypto.Cipher import AES

a = AES.new(iv=b"2daeb325d1a426b2",mode=AES.MODE_CBC,key=b'853b44c73f2e51d7c46fdb7c50c4a891')

print(a.decrypt(enc))
```

### 窃听风云

task.py

```python
from sympy import Integer

PREFIX = "Original Message:"

# 加密函数
def encrypt_message(message_str, key):
    # 添加前缀
    message_with_prefix = PREFIX + message_str
    message = message_with_prefix.encode('utf-8')
    # 原文分组
    blocks_num = (len(message) + 15) // 16
    blocks = [message[i * 16:(i + 1) * 16] for i in range(blocks_num)]
    # 进行填充
    blocks[-1] = blocks[-1].ljust(16,b'\x00')

    # 分组加密
    encrypted_blocks = []
    k = key
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        encrypted_block = (((block_int & 0xFFFFFFFFFFFFFFFF) << 64) | (block_int >> 64))^k #换位异或
        encrypted_blocks.append(encrypted_block)
        k += 1  # 密钥自增1

    # 密文分组拼接
    encrypted_message = b''.join(
        int.to_bytes(int(encrypted_block),16, byteorder='big') for encrypted_block in encrypted_blocks
    )
    return encrypted_message

# 解密函数
def decrypt_message(encrypted_message, key):
    # 密文分组
    blocks_num = len(encrypted_message) // 16
    blocks = [encrypted_message[i * 16:(i + 1) * 16] for i in range(blocks_num)]

    decrypted_blocks = []
    k = key
    # 分组解密
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        decrypted_block = block_int^k
        decrypted_block = (((decrypted_block & 0xFFFFFFFFFFFFFFFF) << 64) | (decrypted_block >> 64))
        decrypted_blocks.append(decrypted_block)
        k += 1  # 密钥自增1

    # 原文分组拼接
    decrypted_message = b''.join(
        int(block_int).to_bytes(16, byteorder='big') for block_int in decrypted_blocks
    )

    # 去除前缀及填充
    if decrypted_message.startswith(PREFIX.encode('utf-8')):
        decrypted_message = decrypted_message[len(PREFIX):]
    return decrypted_message.rstrip(b'\x00').decode('utf-8')

# 测试key
initial_key = Integer(0x1234567890abcdef1234567890abcdef)
# 测试原文
message = "This is a test message."
print("Original Message:", message)
# 加密
encrypted_message = encrypt_message(message, initial_key)
print("Encrypted Message:", encrypted_message.hex())
# 解密
decrypted_message = decrypt_message(encrypted_message, initial_key)
print("Decrypted Message:", decrypted_message)
```

去年熵密杯的题

exp.py

```python
from Crypto.Util.number import *
m = bytes_to_long(PREFIX[8:16].encode()+PREFIX[:8].encode())
c = ""
c_0 = c[:32]

my_key = (m^int(c_0,16))
print(my_key.bit_length())

# 解密
decrypted_message = decrypt_message(bytes.fromhex(c), my_key)
print("Decrypted Message:", decrypted_message)
```

### MITM in the Middle

task.txt

```txt
DH parameters:
p (hex) = fca682ce8e12caba26efccf7110e526db078b05ede4efb3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f0000000000000000000000000000000000000000000000001
g = 2

Observed on the wire:
A (Alice -> network): 1a2e7c9f12d441ad7a3a3072c1b02732cf50e982d5a935cf316241d071de86cb4a9d74e2ad90fcb376894beac5efb90b13e512cd1be7f9be4411a57cb929e987
B (Bob   -> network): 68f414cb6b3b79ed741dfd0e321826d267eaee09dc52034a7e70f50d06eb6c52f7f43a4ef83f105b2a81d612c1798b4c60e1c0e3d0e9ad6f68139827cd661ac9

Mallory replaced public keys:
Mallory->Bob   (M1): 8e74cc11794c6af001fcfd4e4a2a8cbd48914e9734be389e3f1d4a2f3a1f96c378a7b9a4849740031cdc0baec8d5c14631e67f3ae31c1181559769151a08e77d9c6d865cb764702c79ae368cbe8b9cbab41d41528f1f57
Mallory->Alice (M2): 30af7da106610c6d25bdf800ce76436b8a9169cb4bce474de00989a695ec66a825bb8e39ca32a38dc7903270c4c4a94e4ee9302052a79f22b44e2ce1842b725f7bdfecdafc5681186539c38f62fa61d6ccec084daad178

Frames (payloads are AES-128-CBC with IV = 0x00..00, key = MD5(shared)):
[1] Alice -> Bob   | payload (hex): c7194b9b7a709504408dd1541bd65ad028063d0242c81ece09bcfe21be1fc7e6
[2] Bob   -> Alice | payload (hex): 653b1a0e4d0c8c3e522dd5d7429b2bf733df71a721a60dc401c3c3b3759fe3fe

Notes to contestants:

KDF: MD5(shared) (16 bytes)
AES: AES-128-CBC, IV = 0x00...00
Padding: PKCS#7
You are not given any private exponents. Mallory used small exponents (so brute-forcing is feasible). === End of Weakened Wire Log ===
```

貌似是模拟中间人攻击的？

A 给 B 发信息被 M 拦截改成了 M1，B 给 A 发信息被 M 拦截改成了 M2，那我只需要算出 m1 和 m2 就可以得到共享密钥了呗。

exp.py

```python
from hashlib import md5

from Crypto.Cipher import AES

p = int("",16)
g = 2
A = int("",16)
B = int("",16)
M1 = int("",16)
M2 = int("",16)
ct1 = bytes.fromhex("")
ct2 = bytes.fromhex("")
iv = b'\x00'*16
def find_small_exp(pub, limit=2**20):
    cur = 1
    for e in range(1, limit+1):
        cur = (cur * g) % p
        if cur == pub:
            return e
    return None
m1 = find_small_exp(M1, 2**20)
m2 = find_small_exp(M2, 2**20)
if m1 is None or m2 is None:
    raise SystemExit
shared_A = pow(A, m2, p)
shared_B = pow(B, m1, p)
def kdf(shared):
    b = shared.to_bytes((shared.bit_length()+7)//8, 'big')
    return md5(b).digest()
key1 = kdf(shared_A)
key2 = kdf(shared_B)
def aes_cbc_decrypt(key, iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    return pt[:-pad]
pt1 = aes_cbc_decrypt(key1, iv, ct1)
pt2 = aes_cbc_decrypt(key2, iv, ct2)
print(pt1.decode())
print(pt2.decode())
```

这边求出的 m 都很小，sage 自带的 discrete_log 应该也可以出来。

### easy-js

附件是个 jsfuck，f12 输入进去得到`xuzWxNfztPPAqLrFtPPQtL3ctPPQtLCsy7nPwrusz9+089C0xbbQobHb0KGwrNy90KHTxdChsKzLudChz6PQodrA0KHM39ChsKzQocW20KG298/Cu67P38HjvsXSu7DL0rvG39K7yP3T0rTzwKi6xQ==`

后面是 base64+text encoding brute force

### zip^2

无交互闯关

第一关：GCD
第二关

task.txt

```txt

N1=
C1=

N2=
C2=


N3=
C3=

e < 10
明文前6位：666_di
```

爆破一下 e，并且是小 e 攻击，c1 末尾有个未知数，爆破一下也

exp.py

```python
from gmpy2 import iroot
from Crypto.Util.number import *

C1=


for i in range(10):
 C = C1*10 + i
for e in range(3,10):
  m = iroot(crt([C,C2,C3],[N1,N2,N3]),e)
if m[1]:
   print(long_to_bytes(int(m[0])))
```

第三关

task.txt

```txt
通过门限算法分有20个子秘密，只需要10个子秘密就能还原key,下列20个子秘密中插入了1个错值，请你找出这个错误，flag的格式是flag{key_错值},如flag{123456_41_13185303516899396}
(41, 13185303516899396)
(24, 110842258028472)
(99, 35561921514804871872)
(79, 4694187479497061032)
(93, 20290375622403946812)
(61, 462113650903222396)
(62, 534603935547530948)
(31, 1084905877119496)
(32, 1440289089335528)
(71, 1801846046977885496)
(70, 1586657009762953300)
(60, 398495991934339920)
(14, 931432740452)
(84, 8140483160337693792)
(13, 485086380892)
(59, 342785762861262992)
(19, 13427367892146801244)
(9, 20850773892)
(95, 24559612682922053000)
(29, 598420253439932)
(69, 1394622542936810412)
```

shamir 的门限方案，sager 可以直接用拉格朗日插值去算

exp.py

```python
# SageMath 代码
shares = [
    (41, 13185303516899396),
    (24, 110842258028472),
    (99, 35561921514804871872),
    (79, 4694187479497061032),
    (93, 20290375622403946812),
    (61, 462113650903222396),
    (62, 534603935547530948),
    (31, 1084905877119496),
    (32, 1440289089335528),
    (71, 1801846046977885496),
    (70, 1586657009762953300),
    (60, 398495991934339920),
    (14, 931432740452),
    (84, 8140483160337693792),
    (13, 485086380892),
    (59, 342785762861262992),
    (19, 13427367892146801244),
    (9, 20850773892),
    (95, 24559612682922053000),
    (29, 598420253439932),
    (69, 1394622542936810412)
]

from itertools import combinations

R.<x> = QQ[]

for i in range(len(shares)):
    trial_shares = shares[:i] + shares[i+1:]
    for comb in combinations(trial_shares, 10):
        try:
            P = R.lagrange_polynomial(comb)
            key = P(0)
            wrong_count = sum([1 for xi, yi in shares if P(xi) != yi])
            if wrong_count == 1:
                wrong_share = [s for s in shares if P(s[0]) != s[1]][0]
                print(f"flag{{{key}_{wrong_share[0]}_{wrong_share[1]}}}")
                exit()
        except:
            continue

```

### 旋转格栅

task.py

```python
import random
from copy import deepcopy
from secret import FLAG

FLAG = b'flag{xxxxxxxxxxxxx}'

def gen_grille(n):
    half = n // 2
    base = [[0]*half for _ in range(half)]
    coords = [(i,j) for i in range(half) for j in range(half)]
    random.shuffle(coords)
    num_holes = (half*half) // 4
    for i,j in coords[:num_holes]:
        base[i][j] = 1

    grille = [[0]*n for _ in range(n)]
    for i in range(half):
        for j in range(half):
            if base[i][j]:
                grille[i][j] = 1
                grille[j][n-1-i] = 1
                grille[n-1-i][n-1-j] = 1
                grille[n-1-j][i] = 1
    return grille

def rotate_grille_once(g):
    n = len(g)
    return [[g[n-1-j][i] for j in range(n)] for i in range(n)]

def place_flag_into_grid(n, grille, flag_bytes):
    mat = [['.' for _ in range(n)] for _ in range(n)]
    total_holes = sum(sum(row) for row in grille)

    used = 0
    gcur = deepcopy(grille)
    for rot in range(4):
        for i in range(n):
            for j in range(n):
                if gcur[i][j] == 1 and used < len(flag_bytes):
                    ch = chr(flag_bytes[used]) if 32 <= flag_bytes[used] <= 126 else '?'
                    mat[i][j] = ch
                    used += 1
        gcur = rotate_grille_once(gcur)
    for i in range(n):
        for j in range(n):
            if mat[i][j] == '.':
                mat[i][j] = chr(random.randrange(65, 91))  # A-Z
    return mat

def print_matrix(mat):
    for row in mat:
        print(''.join(row))

def main():
    n = 16
    grille = gen_grille(n)
    mat = place_flag_into_grid(n, grille, FLAG)
    print("# n =", n)
    print("# grille ：")
    for row in grille:
        print(''.join(str(x) for x in row))
    print("# matrix：")
    print_matrix(mat)


if __name__ == '__main__':
    main()
```

这玩意给了初始的格栏还有加密方法，就是 flag 依次放入加密

exp.py

```python
import re
from copy import deepcopy

grille_lines = [

]
matrix_lines = [

]
n = 16
grille = [[int(ch) for ch in line] for line in grille_lines]
mat = [list(line) for line in matrix_lines]

def rotate(g):
    n = len(g)
    return [[g[n-1-j][i] for j in range(n)] for i in range(n)]

gcur = deepcopy(grille)
chars = []
for _ in range(4):
    for i in range(n):
        for j in range(n):
            if gcur[i][j] == 1:
                chars.append(mat[i][j])
    gcur = rotate(gcur)

s = ''.join(chars)
m = re.search(r'flag\{[^}]+\}', s)
print(m.group(0) if m else "")


```

### Fragments Rejoined

给了个二进制文件，还是 arm 的，还有一个 py

task.py

```python
import sys
a = 0xD1
b = 0xA4
c = 0xB6

m0 = ((a ^ 0x37) + 0x20) & 0xFF
m1 = (((b << 1) | (b >> 7)) ^ 0x13) & 0xFF
m2 = (c ^ ((a >> 3) | (b << 5))) & 0xFF

hidden0 = (ord('S') ^ m0) & 0xFF
hidden1 = (ord('M') ^ m1) & 0xFF
hidden2 = (ord('4') ^ m2) & 0xFF

hidden0 = (hidden0 ^ 0xAA) & 0xFF
hidden1 = ((hidden1 + 0x55) & 0xFF)
hidden2 = (hidden2 ^ 0x5A) & 0xFF

b0 = (hidden0 ^ 0xAA) ^ m0
b1 = ((hidden1 - 0x55) & 0xFF) ^ m1
b2 = (hidden2 ^ 0x5A) ^ m2

key = bytearray(16)
key[0] = b0
key[1] = b1
key[2] = b2

for i in range(3, 16):
    key[i] = 0

sys.stdout.write("".join("{:02x}".format(x) for x in key))
```

先脱壳，这里直接在 yazi 的 shell 里面操作的

```bash
yazi
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2025
UPX 5.0.2       Markus Oberhumer, Laszlo Molnar & John Reiser   Jul 20th 2025

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     65536 <-     32784   50.02%   macho/arm64   FragmentsRejoined-final

Unpacked 1 file.
```

看了看，主要是类似 sm4+xor，这里数据在`ENCRYPTED_BYTES_XOR`，拉下来写脚本？不会了

### 流量分析

http 在下载文件，全部拉下来，然后每个都是 xor yyyy

这里`secret_read.zip`可以异或后得到`zip`然后里面是个 jwt 加密的东西，解密后得到

```
{
    "user_id": 1,
    "username": "smb2025",
    "level": "admin",
    "exp": 1760320056
}
```

## 总结

我还是太菜了，什么时候才能变强
