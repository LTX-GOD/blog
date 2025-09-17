---
title: 黄河流域CTF-crypto
published: 2025-05-25
pinned: false
description: 黄河流域CTF，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-05-25
pubDate: 2025-05-25
---


## 前言
和睿抗校赛撞了，赛后看看题复现一下，感觉质量很一般

## 题目

### Latice
task.py
```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
import os
from secret import flag
import numpy as np


def gen(q, n, N, sigma):
    t = np.random.randint(0, high=q // 2, size=n)
    s = np.concatenate([np.ones(1, dtype=np.int32), t])
    A = np.random.randint(0, high=q // 2, size=(N, n))
    e = np.round(np.random.randn(N) * sigma**2).astype(np.int32) % q
    b = ((np.dot(A, t) + e).reshape(-1, 1)) % q
    P = np.hstack([b, -A])
    return P, s


def enc(P, M, q):
    N = P.shape[0]
    n = len(M)
    r = np.random.randint(0, 2, (n, N))
    Z = np.zeros((n, P.shape[1]), dtype=np.int32)
    Z[:, 0] = 1
    C = np.zeros((n, P.shape[1]), dtype=np.int32)
    for i in range(n):
        C[i] = (np.dot(P.T, r[i]) + (np.floor(q / 2) * Z[i] * M[i])) % q
    return C


q = 127
n = 3
N = int(1.1 * n * np.log(q))
sigma = 1.0

P, s = gen(q, n, N, sigma)


def prep(s):
    return np.array([int(b) for char in s for b in f"{ord(char):08b}"], dtype=np.int32)


C = enc(P, prep(hint), q)
P = P.tolist()
C = C.tolist()
print(f"{P=}")
print(f"{C=}")
```

第一眼看上去是格+aes，但是注意代码
>encrypted = AES.new(key=key, iv=iv, mode=AES.MODE_CBC).encrypt(b"".join([pad(i.encode(), 16) for i in flag]))

flag头已知的情况下，根据CBC的性质，有`m[:16]`和`c[:16]`，异或就可以得到iv了

exp.py
```python
import numpy as np
from Crypto.Cipher import AES

leak = -3.257518803980229925210589904230583482986646342139415561576950148286382674434770529248486501793457710730252401258721482142654716015216299244487794967600132597049154513815052213387666360825101667524635777006510550117512116441539852315185793280311905620746025669520152068447372368293640072502196959919309286241
key = 
encrypted = 
iv = encrypted[:16] 
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted[16:])
print(decrypted.decode().strip())
```

### sandwitch
task.py
```python
from Crypto.Util.number import *
import gmpy2
flag = b'flag{fake_flag}'
assert len(flag) == 39
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x3
pad1 = b'easy_problem'
pad2 = b'How_to_solve_it'
c = pow(bytes_to_long(pad1 + flag + pad2),e,n)
print(f'n = {n}')
print(f'c = {c}')
```

很经典的copper，高低位已知爆破中间，且已知`len(flag)=39`和`len(pad2)=15`，那么就可以写出如下的式子
$$
c = (256^{54}pad_1+256^{15}flag+pad2)^{e} \mod n
$$

exp.py
```python
from Crypto.Util.number import *
import hashlib
from tqdm import *

def hash(x):
    return hashlib.sha256(x.encode()).digest()

e = 3
n = 
c = 
pad1 = b'easy_problem'
pad2 = b'How_to_solve_it'

pad1 = bytes_to_long(pad1)
pad2 = bytes_to_long(pad2)

PR.<x> = PolynomialRing(Zmod(n))

f = (pad1 * 256 ** 54 + x * 256 ** 15 + pad2 )^e - c
f = f.monic()
res = f.small_roots(X=256^39,beta=1,epsilon=0.04)
if(res != []):
    print(long_to_bytes(int(res[0])))
```

### Happy
task.py
```python
import os, utils
from secret import flag
assert flag.startswith(b'flag{') and flag.endswith(b'}')

seed = int(os.urandom(16).hex(), 16)
gen = utils.Gen(seed)
msg = b'Happy4321: ' + flag
enc = bytes(m ^ next(gen) for m in msg).hex()
print(enc)
```
utils.py
```python
class Gen:
    def __init__(self, state):
        self.nbits = 128
        self.state = state & ((1 << self.nbits) - 1)
        self.mask = 109908700282042807039366676242995409413


    def func0(self, steps=1):
        for _ in range(steps):
            res = self.state & self.mask
            bit = sum([(res >> i) & 1 for i in range(self.nbits)]) & 1
            self.state = ((self.state << 1) ^ bit) & ((1 << self.nbits) - 1)
        return bit

    def __next__(self):
        out = 0
        for _ in range(8):
            bit = self.func0(2023)
            out = (out << 1) ^ bit
        return out
```

和NKCTF2023的题差不多，而且难度减小了一点点，参考[XMCVE](https://sma11pi9.cn/article/example-1)

exp.py
```python
# SageMath
class Gen:
    def __init__(self, state):
        self.nbits = 128
        self.state = state & ((1 << self.nbits) - 1)
        self.mask = 109908700282042807039366676242995409413


    def func0(self, steps=1):
        for _ in range(steps):
            res = self.state & self.mask
            bit = sum([(res >> i) & 1 for i in range(self.nbits)]) & 1
            self.state = ((self.state << 1) ^ bit) & ((1 << self.nbits) - 1)
        return bit

    def __next__(self):
        out = 0
        for _ in range(8):
            bit = self.func0(2023)
            out = (out << 1) ^ bit
        return out

n = 128
msg = b'Happy4321: flag{'
mask = 109908700282042807039366676242995409413

enc = ''
enc = bytes.fromhex(enc)
Round = 2023

# 构建M矩阵
M = matrix(GF(2), n, n)
for i in range(n):
    if i+1<n:
        M[i+1, i] = 1
    if mask&(1<<(n-i-1)):
        M[i, -1] = 1
    else:
        M[i, -1] = 0

# seed * M2 = output_s
M2 = matrix(GF(2), n, n)

for i in range(n):
    tmp = M^(Round*(i+1))
    for y in range(n):
        M2[y, i] = tmp[y, -1]

# 构建output_s矩阵
output_s = []

for i in range(len(msg)):
    tmp = msg[i]^^enc[i]
    for x in range(8):
        if tmp&(1<<(8-x-1)):
            output_s.append(1)
        else:
            output_s.append(0)

output_s = vector(GF(2), output_s)

S = M2.solve_left(output_s)
seed = int(''.join([str(each) for each in S]), 2)
print(seed)

import os

enc = ''
enc = bytes.fromhex(enc)
seed = 16527323701539137374460041583215952894

gen = Gen(seed)
flag = bytes(c ^ next(gen) for c in enc)
print(flag)  
```

### 因式分解
task.py
```python
from Crypto.Util.number import *
from gmpy2 import*
from secret import flag,a,b,c

m = bytes_to_long(flag)
p = getPrime(256)
q = getPrime(256)
n = p * q
e = 65537
_q = int(bin(q)[2:][::-1] , 2)
c = pow(m,e,n)

print('n =',n)
print('c =',c)

assert a**3+b**3+c**3 == 3*a*b*c
gift = secert**3 - 9*secert + 8
print(gift)

assert 3*(p ^ _q) == a + b + c
```

tellasecret.py
```python
import string

from secret import hint
from secret import encrypt

import random

dicts = string.ascii_lowercase +"{=}"

key = (''.join([random.choice(dicts) for i in range(4)])) * 8

assert(len(hint) == 32)

assert(len(key) == 32)


cipher = encrypt(hint, key)

print(cipher)
```

这个东西我是真的看不懂，没get到他到底想让我干什么，对于`_q`肯定是个剪枝了，可以参考[鸡块神的文章](https://tangcuxiaojikuai.xyz/post/342113ee.html)，但是这个serect我是真的没看懂，看了别的师傅的博客我才知道是维吉尼亚爆破，真难绷

exp1.py
```
from itertools import product

dicts = "abcdefghijklmnopqrstuvwxyz{=}"
cipher = "cp=wmaunapgimjfpopeblvup=aywqygb"

# 暴力破解 4 字节 key
for key in product(dicts, repeat=4):
    key = ''.join(key) * 8
    plain = ''
    for i in range(len(cipher)):
        c = dicts.index(cipher[i])
        k = dicts.index(key[i])
        p = (c - k) % 29
        plain += dicts[p]
    if "secret" in plain:
        print("Key:", key[:4])
        print("Plaintext:", plain)
        break
# tellasecret{a=secert}keepsilentt
```

这是第一部分，那么就解出来`a=secert`，看abc的关系式，很经典的轮换式，直接想到`a=b=c`，那么可知`p^_q=a`，解方程求a然后剪枝就行了

exp2.py
```python
gift = 
k = var('secret')

p = k

polys = (p**3 - 9*p + 8 == gift)
x = solve(polys, k)
print(x)

from Crypto.Util.number import *
import sys

sys.setrecursionlimit(1500)

pxorq =
n = 
c = 
e = 65537
pxorq = str(bin(pxorq)[2:]).zfill(256)


def find(ph, qh, pl, ql):
    l = len(ph)
    tmp0 = ph + (256 - 2 * l) * "0" + pl
    tmp1 = ph + (256 - 2 * l) * "1" + pl
    tmq0 = qh + (256 - 2 * l) * "0" + ql
    tmq1 = qh + (256 - 2 * l) * "1" + ql
    if (int(tmp0, 2) * int(tmq0, 2) > n):
        return
    if (int(tmp1, 2) * int(tmq1, 2) < n):
        return
    if (int(pl, 2) * int(ql, 2) % (2 ** (l - 1)) != n % (2 ** (l - 1))):
        return

    if (l == 128):
        pp0 = int(tmp0, 2)
        if (n % pp0 == 0):
            pf = pp0
            qf = n // pp0
            phi = (pf - 1) * (qf - 1)
            d = inverse(e, phi)
            m1 = pow(c, d, n)
            print(long_to_bytes(m1))
            exit()

    else:
        if (pxorq[l] == "1" and pxorq[255 - l] == "1"):
            find(ph + "1", qh + "0", "1" + pl, "0" + ql)
            find(ph + "0", qh + "0", "1" + pl, "1" + ql)
            find(ph + "1", qh + "1", "0" + pl, "0" + ql)
            find(ph + "0", qh + "1", "0" + pl, "1" + ql)
        elif (pxorq[l] == "1" and pxorq[255 - l] == "0"):
            find(ph + "1", qh + "0", "0" + pl, "0" + ql)
            find(ph + "0", qh + "0", "0" + pl, "1" + ql)
            find(ph + "1", qh + "1", "1" + pl, "0" + ql)
            find(ph + "0", qh + "1", "1" + pl, "1" + ql)
        elif (pxorq[l] == "0" and pxorq[255 - l] == "1"):
            find(ph + "0", qh + "0", "1" + pl, "0" + ql)
            find(ph + "0", qh + "1", "0" + pl, "0" + ql)
            find(ph + "1", qh + "0", "1" + pl, "1" + ql)
            find(ph + "1", qh + "1", "0" + pl, "1" + ql)
        elif (pxorq[l] == "0" and pxorq[255 - l] == "0"):
            find(ph + "0", qh + "0", "0" + pl, "0" + ql)
            find(ph + "1", qh + "0", "0" + pl, "1" + ql)
            find(ph + "0", qh + "1", "1" + pl, "0" + ql)
            find(ph + "1", qh + "1", "1" + pl, "1" + ql)


find("1", "1", "1", "1")
```

## 总结
题目质量还行吧？因式分解这玩意前面是维吉尼亚真没想到xd