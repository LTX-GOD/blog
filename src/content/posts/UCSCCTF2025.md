---
title: UCSCCTF2025
published: 2025-04-20
pinned: false
description: UCSCCTF2025 crypto wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-20
pubDate: 2025-04-20
---


## 前言
高铁一个小时速通

## 题目
### XR4
task.py
```python
import base64
import random
from secret import flag
import numpy as np
def init_sbox(key):
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box
def decrypt(cipher, box):
    res = []
    i = j = 0
    cipher_bytes = base64.b64decode(cipher)
    for s in cipher_bytes:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(s ^ k))
    return (''.join(res))
def random_num(seed_num):
    random.seed(seed_num)
    for i in range(36):
        print(chr(int(str(random.random()*10000)[0:2]) ^ (data[i])))

if __name__ == '__main__':
    ciphertext = "MjM184anvdA="
    key = "XR4"
    box = init_sbox(key)
    a=decrypt(ciphertext, box)
    random_num(int(a))
```

有一说一，懒得写，gpt梭哈了
exp.py
```python
import base64

def init_sbox(key: str) -> list[int]:
    """
    初始化 RC4 的 S 盒（KSA 阶段）
    """
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box

def decrypt(cipher: str, box: list[int]) -> str:
    """
    RC4 解密（PRGA 阶段），输入是 base64 编码的密文
    返回解密后的 ASCII 字符串
    """
    res = []
    i = j = 0
    cipher_bytes = base64.b64decode(cipher)
    for byte in cipher_bytes:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(byte ^ k))
    return ''.join(res)

# 测试解密
ciphertext = "MjM184anvdA="
key = "XR4"
seed_str = decrypt(ciphertext, init_sbox(key))
print("[*] RC4 解密后得到的 seed 字符串：", seed_str)

import numpy as np

# 题目给出的转置后矩阵
transposed_matrix = np.array([
    [  1, 111,  38, 110,  95,  44],
    [ 11,  45,  58,  39,  84,   1],
    [116,  19, 113,  60,  91, 118],
    [ 33,  98,  38,  57,  10,  29],
    [ 68,  52, 119,  56,  43, 125],
    [ 32,  32,   7,  26,  41,  41]
])

# 先转置回来，再展平为一维数组
data = transposed_matrix.T.reshape(-1)
import random

def recover_flag(seed: int, data: np.ndarray) -> str:
    random.seed(seed)
    chars = []
    for i in range(len(data)):
        # 取 “[0:2]” 的做法和题目一致
        two_digits = str(random.random() * 10000)[0:2]
        rand_val = int(two_digits)
        chars.append(chr(rand_val ^ data[i]))
    return ''.join(chars)

# 执行还原
seed = int(seed_str)  # 78910112
flag = recover_flag(seed, data)
print("[*] 恢复出的 flag：", flag)
```

### Lunz
task.py
```python
from gmpy2 import *
from hashlib import md5
from Crypto.Util.number import *
from sympy import *

message= xxxxxx
flag = 'flag{'+md5(message).hexdigest()+'}'
p = getPrime(250)
q = getPrime(250)
assert p > q
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
m = bytes_to_long(message)

Rod = getPrime(5)
I = Rod + len(str(Rod))
k = pow(p, Rod)
N = pow(p, I) * q
d1 = getPrime(2000)
d2 = nextprime(d1 + getPrime(1000))
e_1 = inverse(d1, (k * phi))
e_2 = inverse(d2, (k * phi))
c = pow(m,e,n)

print(f'e_1 = {e_1}')
print(f'e_2 = {e_2}')
print(f'N = {N}')
print(f'c = {c}')
```
对某题拙略的模仿罢了xd，d2比d1大1000bits的样子，与d1的比特数差的有点多，考虑构造关于差值的等式进行copper，
消掉d1后得到式子

$$ e_1*e_2*x-(e_1-e_2)=0 \ mod \  phi $$
后面处理次方即可，直接把那个移过去了，结果真出来了xd
原型是D^3ctf的题，应该是个论文题来着

exp.py
```python
e = 65537
e1 = 
e2 = 
N = 
c = 
PR.<x>=PolynomialRing(Zmod(N))
f=e1*e2*x-(e1-e2)
f=f.monic()
root=f.small_roots(X=2^1020,beta=0.75,epsilon=0.05)
print(e1*e2*root[0]-(e1-e2))

from Crypto.Util.number import *
import gmpy2
from hashlib import md5
Rod = getPrime(5)
I = Rod + len(str(Rod))
e = 65537
e1 = 
e2 = 
N = 
c = 
g=
p=gmpy2.iroot(gmpy2.gcd(g,N),Rod)[0]
q=N//(p**I)
d=gmpy2.invert(0x10001,(p-1)*(q-1))
msg=long_to_bytes(pow(c,d,p*q))
print(msg)
flag = 'flag{'+md5(msg).hexdigest()+'}'
print(flag)
```

### essential
原题，不放了xd

### MERGE_ECC
task.py
```python
import random
from sympy import nextprime
def part1():
    p = random_prime(2^512, 2^513)
    a = random.randint(0, p-1)
    b = random.randint(0, p-1)
    while (4 * a**3 + 27 * b**2) % p == 0:
        a = random.randint(0, p-1)
        b = random.randint(0, p-1)

    E = EllipticCurve(GF(p), [a, b])

    P=E.random_point()

    n = [random.randint(1, 2**20) for _ in range(3)] 
    assert part1=''.join([hex(i)[2:] for i in n])
    cipher = [n[i] * P for i in range(3)]

    print(f"N = {p}")
    print(f"a = {a}, b = {b}")
    print(f"P = {P}")
    for i in range(3):
        print(f"cipher{i} = {cipher[i]}")
def part2():
    p =  
    a =  
    b =  
    P = E.random_point()
    Q = key*P
    print("p = ",p)
    print("a = ",a)
    print("b = ",b)
    print("P = ",P)
    print("Q = ",Q)
    assert part2=key
part1()
print("-------------------------------------------")
part2()
assert flag="flag{"+str(part1)+"-"+str(part2)+"}"


```
part1暴力求解，part2是SmartAttack

exp.py
```python

import math

def inv_mod(x: int, p: int) -> int:
    return pow(x, p-2, p)

def point_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P != Q:
        lam = ((y2 - y1) * inv_mod(x2 - x1, p)) % p
    else:
        lam = ((3 * x1 * x1 + a) * inv_mod(2 * y1, p)) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(P, n, a, p):
    R = None      # 初始结果为无穷远点
    Q = P         # 临时变量 Q = P, 逐位处理 n
    while n > 0:
        if n & 1:
            R = point_add(R, Q, a, p)
        Q = point_add(Q, Q, a, p)
        n >>= 1
    return R

def dlog_bsgs(P, Q, order_bound, a, p):
    m = int(math.ceil(math.sqrt(order_bound)))
    table = {}
    R = None
    for j in range(m):
        table[R] = j
        R = point_add(R, P, a, p)
    mP = scalar_mul(P, m, a, p)
    neg_mP = (mP[0], (-mP[1]) % p) if mP is not None else None

    S = Q
    for i in range(m):
        if S in table:
            return i * m + table[S]
        S = point_add(S, neg_mP, a, p)
    return None 

def attack_part1():
    p1 = 
    a1 = 
    b1 = 
    P1 = ()
    cipher = []

    bound = 2**20
    ns = []
    for i in range(3):
        ni = dlog_bsgs(P1, cipher[i], bound, a1, p1)
        assert ni is not None, "Part1 的 n{} 恢复失败！".format(i)
        ns.append(ni)
    print("Part1 恢复出的 n 值：", ns)
    hex_str = ''.join([hex(x)[2:] for x in ns])
    print("拼接后的十六进制字符串：", hex_str)
    return hex_str


if __name__ == "__main__":
    part11 = attack_part1()
    print(part11)

from sage.all import *
from Crypto.Util.number import *
p =  
a =  
b =  
E = EllipticCurve(GF(p),[a,b])
P =  E()
Q =  E()
print(p== E.order())
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)
m3 = SmartAttack(P,Q,p)
print(m3)
```

### Ez_Calculate
task.py
```python
from Crypto.Util.number import *
from random import randint
from hashlib import md5

flag1 = b'xxx'
flag2 = b'xxx'
Flags = 'flag{' + md5(flag1+flag2).hexdigest()[::-1] + '}'

def backpack_encrypt_flag(flag_bytes, M, group_len):
    bits = []
    for byte in flag_bytes:
        bits.extend([int(b) for b in format(byte, "08b")])

    while len(bits) % group_len != 0:
        bits.append(0)

    S_list = []
    for i in range(0, len(bits), group_len):
        group = bits[i:i + group_len]
        S = sum(bit * m for bit, m in zip(group, M))
        S_list.append(S)
    return S_list

def backpack(flag_bytes):
    R = [10]
    while len(R) < 8:
        next_val = randint(2 * R[-1], 3 * R[-1])
        R.append(next_val)
    B = randint(2 * R[-1] + 1, 3 * R[-1])
    A = getPrime(100)
    M = [A * ri % B for ri in R]
    S_list = backpack_encrypt_flag(flag_bytes, M, len(M))
    return R, A, B, M, S_list

p = getPrime(512)
q = getPrime(512)
n = p*q
e = 0x10000
m = bytes_to_long(flag1)
k = randint(1, 999)
problem1 = (pow(p,e,n)-pow(q,e,n)) % n
problem2 = pow(p-q,e,n)*pow(e,k,n)
c = pow(m,e,n)

R, A, B, M, S_list = backpack(flag2)

with open(r"C:\Users\Rebirth\Desktop\data.txt", "w") as f:
    f.write(f"problem1 = {problem1}\n")
    f.write(f"problem2 = {problem2}\n")
    f.write(f"n = {n}\n")
    f.write(f"c = {c}\n")
    f.write("-------------------------\n")
    f.write(f"R = {R}\n")
    f.write(f"A = {A}\n")
    f.write(f"B = {B}\n")
    f.write(f"M = {M}\n")
    f.write(f"S_list = {S_list}\n")
    f.write("-------------------------\n")
    f.write(f"What you need to submit is Flags!\n")

```

part1多次rabin，part2当背包写

exp.py
```python
problem1 = 
problem2 = 
n = 
c = 
e = 0x10000
from Crypto.Util.number import *
import gmpy2
# problem1 = (pow(p,e,n)-pow(q,e,n)) % n
# problem2 = pow(p-q,e,n)*pow(e,k,n)
for k in range(1, 999):
   tmp = problem1+problem2//pow(e,k,n)

   p = gmpy2.gcd(n,tmp)
   q = n // p
   if q!=1 and p!=1:
       print(p,q)

p=
q=n//p
inv_p = gmpy2.invert(p, q)
inv_q = gmpy2.invert(q, p)

cs = [c]
for i in range(16):
    ps = []
    for c2 in cs:
        r = pow(c2, (p + 1) // 4, p)
        s = pow(c2, (q + 1) // 4, q)

        x = (r * inv_q * q + s * inv_p * p) % n
        y = (r * inv_q * q - s * inv_p * p) % n
        if x not in ps:
            ps.append(x)
        if n - x not in ps:
            ps.append(n - x)
        if y not in ps:
            ps.append(y)
        if n - y not in ps:
            ps.append(n - y)
    cs = ps

for m in cs:
    print(long_to_bytes(m))

from Crypto.Util.number import inverse

def decrypt_backpack(R, A, B, S_list):
    invA = inverse(A, B)
    
    bits = []
    for S in S_list:
        s = (invA * S) % B
        
        group_bits = []
        for r in reversed(R):
            if s >= r:
                group_bits.append(1)
                s -= r
            else:
                group_bits.append(0)
        bits.extend(reversed(group_bits))
    
    flag2_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        flag2_bytes.append(byte)

    return bytes(flag2_bytes).rstrip(b'\x00')


if __name__ == "__main__":
    R = [10, 29, 83, 227, 506, 1372, 3042, 6163]
    A = 1253412688290469788410859162653
    B = 16036
    M =
    S_list = 

    flag2 = decrypt_backpack(R, A, B, S_list)
    print("解密得到的 flag2 =", flag2)

from hashlib import md5

flag1=b'CRYPTO_ALGORIT'
flag2=b'HMS_WELL_DONE'
Flags = 'flag{' + md5(flag1+flag2).hexdigest()[::-1] + '}'
print(Flags)
```

### Logos
参考 https://blog.csdn.net/luochen2436/article/details/132332081 即可

## 总结
一个小时速通包爽的，但是原题太多了，真没意思xd