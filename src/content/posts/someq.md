---
title: NewStar2025 部分wp
published: 2025-10-06
pubDate: 2025-10-06
description: newstar2025 wp
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false
licenseName: "MIT"
lang: "zh_CN"
encrypted: true
password: "mnbvcxz123321.A"
---

## 前言

国庆先来无事，随便看看

## week1

这个就省略了，太简单了

## week2

写部分题吧

### RSA_revenge

task.py

```python
# 这段脚本把 flag 拆成两半并分别加密

from Crypto.Util.number import *
import random


# 原始 flag
flag = b'flag{???????????????????}'
length = len(flag)

# 把 flag 分成前后两半，分别转换为整数 m1, m2
m1 = bytes_to_long(flag[:length//2])
m2 = bytes_to_long(flag[length//2:])

# ------------------------- par1: 构造第1类模 n1 并加密 m -------------------------
def par1(m):

    lst = []
    # 选取 3 个不同的大素数（每个 512 bit）
    while len(lst) < 3:
        prime = getPrime(512)
        if prime not in lst:
            lst.append(prime)
            print(prime)

    # n1 = ∏ p_i^{t_i}，其中每个素因子 p_i 被随机提升到 2到7 的小幂
    n1 = 1
    for prime in lst:
        tmp = random.randint(2, 7)   # 指数 tmp 在 2到7 之间
        print(tmp)
        n1 *= prime ** tmp

    e = 65537
    # 在模 n1 下对 m 做 RSA 加密
    c1 = pow(m, e, n1)

    # 输出素因子列表、模 n1、密文 c1

    print(f"list：{lst}")
    print(f"n1={n1}")
    print(f"c1={c1}")


# ------------------------- par2: 构造第2类模 n2 并加密 m，给出多个 hint -------------------------
def par2(m):

    # 随机选三个不同的大素数 p2,q2,r2（每个 512 bit），并把它们相乘得到 n2
    while True:
        p2 = getPrime(512)
        q2 = getPrime(512)
        r2 = getPrime(512)
        if p2 != q2 and p2 != r2 and q2 != r2:
            break

    n2 = p2 * q2 * r2


    hint1 = pow(m, p2 * q2, n2)
    hint2 = pow(m, r2, n2)        # 怎么用好 hint1 和 hint2 呢？试一试 Fermat 吧！
    hint3 = p2 + q2               # hint3 很关键 —— 想想如果你知道 p+q 和 p*q，就能做什么？

    e = 65537
    c2 = pow(m, e, n2)

    print(f"n2={n2}")
    print(f"hint1={hint1}")
    print(f"hint2={hint2}")
    print(f"hint3={hint3}")
    print(f"c2={c2}")


# 分别运行两部分，对 flag 的前半段/后半段加密并输出相关提示
par1(m1)
par2(m2)
```

先看 part1，你可以发现 list 就是`pqr`，后面进行什么次方啊什么的，那我每个都除一下就可以得到次方了

```python
p =
q =
r =
n1 =
tmp = n1
a = 0
while tmp % p == 0:
    tmp = tmp // p
    a += 1
b = 0
while tmp % q == 0:
    tmp = tmp // q
    b += 1
c = 0
while tmp % r == 0:
    tmp = tmp // r
    c += 1
print(a, b, c)
print(tmp)
```

得到`a=3, b=5, c=7`，然后算 flag1 即可，这里 crt 求解即可

```python
from sympy.ntheory.modular import crt

from Crypto.Util.number import *

p =
q =
r =
n1 =
c1 =
e = 65537
a = 3
b = 5
c = 7
phi_p = (p - 1) * (p ** (a - 1))
phi_q = (q - 1) * (q ** (b - 1))
phi_r = (r - 1) * (r ** (c - 1))
d_p = pow(e, -1, phi_p)
d_q = pow(e, -1, phi_q)
d_r = pow(e, -1, phi_r)
pa = p ** a
qb = q ** b
rc = r ** c
c1_p = c1 % pa
c1_q = c1 % qb
c1_r = c1 % rc
m_p = pow(c1_p, d_p, pa)
m_q = pow(c1_q, d_q, qb)
m_r = pow(c1_r, d_r, rc)
res = crt([pa, qb, rc], [m_p, m_q, m_r])
m1 = res[0]
flag1 = long_to_bytes(m1)
print(flag1)
```

继续看 part2，提示是费马定理，往上面靠一点点就好了。

$$
h_2^{pq} = m^{pqr} = (m^{pq})^r = h_1^r \pmod{n} \\
h_2^{pqr}=(h_1^{r})^r \pmod{n}=(h_1^{r})^r \pmod{r} \\
由费马定理得 \\
h_2^n=h_1 \pmod{r} \\
kr=h_2^n-h_1
$$

r 通过 gcd 求出，然后就出来了

```
from Crypto.Util.number import *

n2 =
c2 =
hint1 =
hint3 =
hint2=

r=GCD(pow(hint2,n2,n2)-hint1,n2)

d=inverse(65537,r-1)
print(long_to_bytes(pow(c2,d,r)))
```

### FHE: 0 and 1

task.py

```python
import uuid
import random
from Crypto.Util.number import getPrime

flag = "flag{" + str(uuid.uuid4()) + "}"  # 生成随机 flag
binary_flag = ""  # 存储 flag 对应的二进制字符串

# 将每个字符转换为 8 位二进制
for ch in flag:
    # ord(ch) 得到字符的 ASCII 值
    # bin(...) 得到二进制字符串，去掉 '0b' 前缀并补齐 8 位
    binary_flag += bin(ord(ch))[2:].zfill(8)

p = getPrime(128)   # 生成大素数 p

# -------------------------------
# 加密逻辑
# -------------------------------
ciphertext = []  # 存储加密后的每一位
public_keys = []  # 存储每一位对应的 public key

for bit in binary_flag:
    # 随机生成一个大整数作为公钥
    rand_multiplier = random.randint(p // 4, p // 2)
    rand_offset = random.randint(1, 10)
    pk_i = p * rand_multiplier + rand_offset
    public_keys.append(pk_i)

    # 加密：bit + 一个小随机数 + p 的倍数
    small_noise = 2 * random.randint(1, p // 2**64)
    large_noise = p * random.randint(p // 4, p // 2)
    c_i = int(bit) + small_noise + large_noise
    ciphertext.append(c_i)

# -------------------------------
# 保存公钥和密文到文件
# -------------------------------
with open("pk.txt", "w") as f:
    f.write(str(public_keys))

with open("c.txt", "w") as f:
    f.write(str(ciphertext))
```

FHE 问题，看看代码，主要是找 p，很明显的思路就是通过 gcd 求 p，这里我枚举偏移量去算 p。

继续看 c 这玩意

$$
c_i=b_i+2*s_i+p*l_i \\
c_i \pmod{p}=b_i+2*s_i \pmod{p} \\
(c_i \pmod{p}) \pmod{2}=b_i
$$

那么就只剩 01 两种可能性了，这里直接搓脚本

```python
import ast
from math import gcd

with open("pk.txt", "r") as f:
    pk_str = f.read()
public_keys = ast.literal_eval(pk_str)

with open("c.txt", "r") as f:
    c_str = f.read()
ciphertext = ast.literal_eval(c_str)

p = None
for i in range(1, len(public_keys)):
    pk0 = public_keys[0]
    pki = public_keys[i]
    for o0 in range(1, 11):
        for oi in range(1, 11):
            a = pk0 - o0
            b = pki - oi
            if a < 0 or b < 0:
                continue
            g = gcd(a, b)
            if 120 < g.bit_length() < 140:
                valid = True
                for pk in public_keys:
                    r = pk % g
                    if not (1 <= r <= 10):
                        valid = False
                        break
                if valid:
                    p = g
                    break
        if p is not None:
            break
    if p is not None:
        break

if p is None:
    raise ValueError("Could not find p. Try running again or check files.")

binary_flag = ""
for c in ciphertext:
    remainder = c % p
    bit = remainder % 2
    binary_flag += str(bit)

flag = ""
for i in range(0, len(binary_flag), 8):
    byte = binary_flag[i:i+8]
    ch = chr(int(byte, 2))
    flag += ch

print(flag)
```

### 群论小测试

挺有意思的一个交互游戏

看这个题，首先确定阶数，然后找单位元 e，再看看对称不对称，其实这个题好像光看阶数就行了？

### 欧皇的生日

task.py

```python
import random
from secret import flag

m = 2**22
a = random.randint(1, m-1)
b = random.randint(1, m-1)
c = random.randint(1, m-1)

def Hash(x):
    return (a*x**2 + b*x + c) % m

print("Find a collision: give me two different numbers x1, x2 with Hash(x1)=Hash(x2).")
print("Input Format: x1 x2")

cnt = 0
while cnt < 5000:
    data = input(":").strip().split()
    if len(data) != 2:
        print("Need two numbers!")
        continue
    try:
        x1, x2 = map(int, data)
    except:
        print("Invalid input")
        continue

    cnt += 1
    x1 %= m
    x2 %= m
    if x1 != x2 and Hash(x1) == Hash(x2):
        print(flag)
        break
    else:
        print("x")
        print(Hash(x1),Hash(x2))
```

匹配两个数出来的值一样就行了，打表就行

```python
from pwn import *

host = "39.106.48.123"
port =

conn = remote(host, port)

conn.recvuntil(b"Input Format: x1 x2\n")

m = 2**22
hashes_seen = {}

for i in range(5000):
    payload = f"{i} {i+1}"
    conn.sendline(payload.encode())

    conn.recvuntil(b"x\n")
    line = conn.recvline().strip().decode()
    h_i, _ = map(int, line.split())

    if (i % 100 == 0):
        print(f"[*] Queried {i} inputs, found {len(hashes_seen)} unique hashes...")

    if h_i in hashes_seen:
        x1 = i
        x2 = hashes_seen[h_i]
        collision_payload = f"{x1} {x2}"
        conn.sendline(collision_payload.encode())
        print("\n[+] Flag:")
        response = conn.recvall(timeout=2)
        print(response.decode())

        break
    else:
        hashes_seen[h_i] = i

conn.close()
```

### GCL

task.py

```python
from Crypto.Util.number import *
import uuid
import random

flag="flag{"+str(uuid.uuid4())+"}"
m=bytes_to_long(flag.encode())
length=m.bit_length()


def encrypt(m):
    gift=[]
    p=getPrime(length+1)
    a=random.randint(2,p-1)
    b=random.randint(2,p-1)

    s=random.randint(2,p-1)
    while len(gift)<10:
        s=(a*inverse(s,p)+b)%p
        if s!=0:
            gift.append(s)
        else:
            gift=[]
            s=random.randint(2,p-1)

    key=(a*inverse(s,p)+b)%p
    return m^key,gift


c,gift=encrypt(m)
print("c=",c)
print("gift=",gift)
```

直接逆就行了

```python
from math import gcd

c =
gift = []

n = len(gift)
Ds = []
for i in range(n - 3):
    s0 = gift[i]
    s1 = gift[i + 1]
    s2 = gift[i + 2]
    s3 = gift[i + 3]
    left = s1 * (s0 - s2) * (s1 - s2)
    right = s2 * (s1 - s3) * (s0 - s1)
    D = left - right
    Ds.append(D)

p = abs(Ds[0])
for d in Ds[1:]:
    p = gcd(p, d)
print(f"p = {p}")

g0, g1, g2 = gift[0], gift[1], gift[2]
diff = (g0 - g1) % p
num = (g0 * g1 - g1 * g2) % p
inv_diff = pow(diff, -1, p)
b = (num * inv_diff) % p

a = (g1 * g0 - b * g0) % p

s_last = gift[-1]
inv_s = pow(s_last, -1, p)
key = (a * inv_s + b) % p
m = c ^ key

flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
flag = flag_bytes.decode('utf-8')
print(f"flag = {flag}")
```

### 随机数之旅 3

task.py

```python
# Sage 9.3
import random
import uuid

flag="flag{"+str(uuid.uuid4())+"}"

n=len(flag)
m=n-1
p=random_prime(2**20)

A=[random.randint(p//2,p-1) for _ in range(m*n)]
A=matrix(Zmod(p),m,n,A)

x=[ord(i) for i in flag]
x=vector(x)

b=A*x

with open("output.txt","w") as f:
    f.write(str(p)+"\n")
    f.write(str(list(A))+"\n")
    f.write(str(list(b)))
```

exp.py

```python
p = 5323
A_list =
b_list =
R = Zmod(p)
A = Matrix(R, A_list)
b = vector(R, b_list)

x0 = A.solve_right(b)

kernel_basis = A.right_kernel().basis()
v = kernel_basis[0]

v_int = [int(v_i) for v_i in v]
x0_int = [int(x0_i) for x0_i in x0]
n = len(x0_int)

best_k = None
flag_chars = ""

for k in range(p):
    x_k_int = [(x0_int[i] + k * v_int[i]) % p for i in range(n)]

    is_valid = True
    for val in x_k_int:
        if not (32 <= val <= 126):
            is_valid = False
            break

    if is_valid:
        try:
            temp_flag = "".join([chr(val) for val in x_k_int])
        except ValueError:
            continue

        if temp_flag.startswith("flag{") and temp_flag.endswith("}"):
            print(f"找到可能的 k: {k}")
            flag_chars = temp_flag
            best_k = k
            break
print(flag_chars)

```

### CBC 之舞

task.py

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

BLOCK_SIZE = 16
key = os.urandom(16)
iv2 = os.urandom(16)


#flag为m2的部分内容
cipher = AES.new(key, AES.MODE_CBC, iv2)
padded_m2 = pad(m2, AES.block_size)
print(len(padded_m2))
c2 = cipher.encrypt(padded_m2)
c2_blocks = [c2[i:i+16] for i in range(0, len(c2), 16)]
print(len(c2_blocks))

#偶不，这段不应该被你们看见的
# perm = [1, 2, 3, 0]
# random.shuffle(perm)
# while any(i == perm[i] for i in range(4)):
#     random.shuffle(perm)


c1_blocks = [c2_blocks[i] for i in perm]
c1 = b''.join(c1_blocks)


iv1 = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv1)
m1 = cipher.decrypt(c1)


print("IV1 (hex):", iv1.hex())
print("IV2 (hex):", iv2.hex())
print("m1 (hex):", m1.hex())
print("c1 (hex):", c1.hex())
print("c2 (hex):", c2.hex())
```

这个不是特别熟，ai 一把梭哈

exp.py

```python
import binascii

from Crypto.Util.Padding import unpad

IV1_hex = ""
IV2_hex = ""

m1_hex = (""
          ""
          "")

c1_hex = (""
          ""
          "")

c2_hex = (""
          ""
          "")
def to_blocks(b: bytes, block_size=16):
    return [b[i:i+block_size] for i in range(0, len(b), block_size)]

IV1 = binascii.unhexlify(IV1_hex)
IV2 = binascii.unhexlify(IV2_hex)
m1 = binascii.unhexlify(m1_hex)
c1 = binascii.unhexlify(c1_hex)
c2 = binascii.unhexlify(c2_hex)

m1_blocks = to_blocks(m1, 16)
c1_blocks = to_blocks(c1, 16)
c2_blocks = to_blocks(c2, 16)

perm = []
for b in c1_blocks:
    try:
        idx = c2_blocks.index(b)
    except ValueError:
        raise ValueError("在 c2 中找不到 c1 的某个块，输入可能不一致")
    perm.append(idx)

print("Recovered permutation (perm):", perm)

num_blocks = len(c2_blocks)
X = [None] * num_blocks

X_perm0 = bytes(x ^ y for x, y in zip(m1_blocks[0], IV1))
X[perm[0]] = X_perm0

for i in range(1, len(m1_blocks)):
    left = m1_blocks[i]
    prev_c2_block = c2_blocks[perm[i-1]]
    X_perm_i = bytes(x ^ y for x, y in zip(left, prev_c2_block))
    X[perm[i]] = X_perm_i

P2_blocks = []
for j in range(num_blocks):
    prev = IV2 if j == 0 else c2_blocks[j-1]
    Pj = bytes(x ^ y for x, y in zip(X[j], prev))
    P2_blocks.append(Pj)

m2 = b"".join(P2_blocks)

try:
    m2_unpadded = unpad(m2, 16)
except ValueError:
    print("m2 (hex):", m2.hex())
    print("m2 (raw bytes):", m2)
    raise

print("Recovered m2 (hex):", m2_unpadded.hex())
try:
    print("Recovered m2 (ascii):", m2_unpadded.decode('utf-8', errors='replace'))
except Exception:
    print("Recovered m2 (bytes):", m2_unpadded)

import re

s = m2_unpadded.decode('utf-8', errors='ignore')
m = re.search(r"flag\{.*?\}", s, flags=re.IGNORECASE)
if m:
    print("Found flag:", m.group(0))
else:
    print("No obvious flag{...} pattern found in recovered m2. 原文如下：")
    print(s)

```

### 被泄露的素数

task.py

```python
from Crypto.Util.number import *
import gmpy2

nbits = 2048
p = getPrime(nbits//2)
q = getPrime(nbits//2)
n = p*q
e = 65537


p_bits = int(p).bit_length()
high_bit_count = int(p_bits * 2/3)
p_high = p >> (p_bits - high_bit_count)


mask = (1 << (high_bit_count - '?')) - 1
p_high_masked = p_high & mask


with open("public_key.pem", "w") as f:
    f.write(f"n = {n}\ne = {e}")


with open("partial_p.txt", "w") as f:
    hex_str = hex(p_high_masked)[2:]
    f.write("???" + hex_str)



c = pow(bytes_to_long(flag), e, n)
with open("ciphertext.bin", "wb") as f:
    f.write(long_to_bytes(c))
```

泄露高位，但是莫名其妙的？是什么意思，xd 真的不清楚，猜测是被杀掉了几位，这里把 p 泄露的板子丢给 ai，然后让他改一下爆破几位就行了

exp.py

```python
from sage.all import *

n = Integer()
known_high_hex = ""
p_bitlen = 1024
known_high_bitlen = 682

known_high_int = Integer(int(known_high_hex, 16))
known_high_hex_bits = len(known_high_hex) * 4
masked_bits = known_high_bitlen - known_high_hex_bits
shift = p_bitlen - known_high_bitlen


betas = [0.25, 0.30, 0.33, 0.35, 0.40]
found = None

for prefix in range(1 << masked_bits):
    A = (Integer(prefix) << known_high_hex_bits) + known_high_int
    PR = PolynomialRing(Zmod(n), 'x')
    x = PR.gen()
    f = A * (2**shift) + x
    X = 2**shift
    for beta in betas:
        try:
            roots = f.small_roots(X=X, beta=beta)
        except Exception:
            roots = []
        if not roots:
            continue
        for r in roots:
            p_cand = Integer(A * (2**shift) + Integer(r))
            if n % p_cand == 0:
                q_cand = n // p_cand
                if p_cand.is_prime() and q_cand.is_prime():
                    found = (p_cand, q_cand, prefix, beta)
                    break
        if found:
            break
    if found:
        break

if found:
    p_cand, q_cand, prefix, beta = found
    print("find p！")
    print("prefix =", prefix, "beta =", beta)
    print("p (hex) =", hex(p_cand))
    print("q (hex) =", hex(q_cand))
else:
    print("I am sb")

```

### 随机数之旅 4

task.py

```python
from Crypto.Util.number import getPrime
from Crypto.Util.number import bytes_to_long as b2l
import random
import uuid

p=getPrime(32)
print(p)

flag="flag{"+str(uuid.uuid4())+"}"
pieces=[flag[i:i+3] for i in range(0,len(flag),3)]
c=[b2l(i.encode()) for i in pieces]

x=[random.randint(1,p-1) for i in range(14)]

for i in range(100):
    s=sum(c[i]*x[-14+i] for i in range(14))
    x.append(s%p)

print(x[-28:])
```

懒了，ai 一把梭试试（

exp.py

```python
from Crypto.Util.number import long_to_bytes

p = 3028255493
ys = [2981540507, 1806477191, 1912594455, 2801509477, 401085215, 818458584, 2397034605, 2120401989, 2008340439, 66147874, 1558789534, 2187085801, 671267991, 2930313508, 924435370, 902711250, 1226810076, 769329795, 2328739529, 1228810265, 1382003520, 1967489557, 2811050420, 1008248532, 1643249997, 639108823, 449982542, 1325050025]

n = 14
A = [[ys[t+j] % p for j in range(n)] for t in range(n)]
b = [ys[t+n] % p for t in range(n)]

def modinv(a, mod):
    return pow(a, mod-2, mod)

def solve_mod(A, b, mod):
    A = [row[:] for row in A]
    b = b[:]
    n = len(A)
    for i in range(n):
        pivot = i
        while pivot < n and A[pivot][i] == 0:
            pivot += 1
        if pivot != i:
            A[i], A[pivot] = A[pivot], A[i]
            b[i], b[pivot] = b[pivot], b[i]
        inv = modinv(A[i][i], mod)
        A[i] = [(val * inv) % mod for val in A[i]]
        b[i] = (b[i] * inv) % mod
        for r in range(n):
            if r != i and A[r][i] != 0:
                factor = A[r][i]
                A[r] = [ (A[r][c] - factor * A[i][c]) % mod for c in range(n) ]
                b[r] = (b[r] - factor * b[i]) % mod
    return b

c = solve_mod(A, b, p)
pieces = []
for val in c:
    bs = long_to_bytes(val)
    try:
        s = bs.decode('utf-8')
    except:
        s = bs.decode('latin-1', errors='replace')
    pieces.append((val, bs, s))

for v,bs,s in pieces:
    print(v, bs, repr(s))

flag = "".join([s for (_,_,s) in pieces])
print(flag)

```

### 独一无二

task.py

```python
# Sage 9.3
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from sympy import prevprime
import uuid
import random
import os

d=os.urandom(16)
D=b2l(d)
flag = f"flag{{{uuid.uuid4()}}}"
cipher=AES.new(d,AES.MODE_ECB)
ct=cipher.encrypt(pad(flag.encode(),16))
print("ct=",ct)

mes1=b"If you used the same random number when signing,"
mes2=b" then you need to be careful."
e1, e2 = b2l(mes1), b2l(mes2)

p=random_prime(2**128)
A,B=random.randint(1,p-1),random.randint(1,p-1)
E = EllipticCurve(Zmod(p),[A, B])
G=E.gens()[0]
n = prevprime(E.order())
print("n=",n)

k=random.randint(1,n-1)
Q=k*G
r=int(Q[0])%n
k_inv = pow(k, -1, n)
assert r!=0

s1 = (k_inv * (e1 + r * D)) % n
s2 = (k_inv * (e2 + r * D)) % n
print("(r1,s1)=",(r,s1))
print("(r2,s2)=",(r,s2))
```

板子题

exp.py

```python
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.Padding import unpad

ct =
n =
r =
s1 =
s2 =

mes1 = b"If you used the same random number when signing,"
mes2 = b" then you need to be careful."
e1, e2 = b2l(mes1), b2l(mes2)

diff_e = (e1 - e2) % n
diff_s = (s1 - s2) % n
k = (diff_e * pow(diff_s, -1, n)) % n

D = ((k * s1 - e1) * pow(r, -1, n)) % n

d_bytes = l2b(D).rjust(16, b'\x00')

cipher = AES.new(d_bytes, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct), 16)

print("AES key (hex):", d_bytes.hex())
print("flag:", pt.decode())


```

### 共轭迷宫

task.py

```python
import numpy as np
from math import sqrt,pi,cos,sin
import hashlib
from decimal import Decimal, getcontext

class Quaternion:
    def __init__(self, w, x, y, z):
        self.w = w
        self.x = x
        self.y = y
        self.z = z

    def __mul__(self, other):
        w1, x1, y1, z1 = self.w, self.x, self.y, self.z
        w2, x2, y2, z2 = other.w, other.x, other.y, other.z
        w = w1 * w2 - x1 * x2 - y1 * y2 - z1 * z2
        x = w1 * x2 + x1 * w2 + y1 * z2 - z1 * y2
        y = w1 * y2 - x1 * z2 + y1 * w2 + z1 * x2
        z = w1 * z2 + x1 * y2 - y1 * x2 + z1 * w2
        return Quaternion(w, x, y, z)


    def inv(self):
        norm_sq = self.w**2 + self.x**2 + self.y**2 + self.z**2
        if abs(norm_sq) < 1e-10:
            raise ValueError("Cannot invert quaternion with zero norm")
        return Quaternion(self.w/norm_sq, -self.x/norm_sq, -self.y/norm_sq, -self.z/norm_sq)

    def conjugate(self):
        return Quaternion(self.w, -self.x, -self.y, -self.z)

    def norm(self):
        getcontext().prec = 50
        w = Decimal(self.w)
        x = Decimal(self.x)
        y = Decimal(self.y)
        z = Decimal(self.z)
        norm_sq = w * w + x * x + y * y + z * z
        n = norm_sq.sqrt()

        return Quaternion(w/n, x/n, y/n, z/n),norm_sq,n


    def __str__(self):
        return f"{self.w}+{self.x}i+{self.y}j+{self.z}k"

    def __eq__(self, other):
        return (abs(self.w - other.w) < 1e-10 and
                abs(self.x - other.x) < 1e-10 and
                abs(self.y - other.y) < 1e-10 and
                abs(self.z - other.z) < 1e-10)


def generate_weak_private_key(g,angle_degrees=45):
    getcontext().prec=50
    x=Decimal(g.x)
    y=Decimal(g.y)
    z=Decimal(g.z)
    g_vector_norm = Decimal(sqrt(x ** 2 + y ** 2 + z ** 2))
    if g_vector_norm < 1e-10:
        return Quaternion(np.cos(np.radians(angle_degrees)),
                          np.sin(np.radians(angle_degrees)), 0, 0).norm()[0]
    u_x = x / g_vector_norm
    u_y = y / g_vector_norm
    u_z = z / g_vector_norm

    angle_rad = Decimal(angle_degrees) * Decimal(pi) / Decimal(180)
    half_angle = angle_rad / Decimal(2)
    w = Decimal(cos(float(half_angle)))
    sin_half = Decimal(sin(float(half_angle)))
    x = sin_half * u_x
    y = sin_half * u_y
    z = sin_half * u_z

    return Quaternion(w, x, y, z)

def encode_flag(flag):
    flag_bytes = flag
    parts = [flag_bytes[0:9], flag_bytes[9:18], flag_bytes[18:27], flag_bytes[27:36]]
    print(parts)
    return tuple(int.from_bytes(part, 'big') for part in parts)




def main():
    flag=b'flag{REDACTED}'
    w, x, y, z = encode_flag(flag)
    #生成元g
    g = Quaternion(w, x, y, z)
    print(g)
    print(f'norm_squared={g.norm()[1]}')
    g=g.norm()[0]
    #Alice的私钥a
    a = generate_weak_private_key(g)
    #Alice的公钥P_A
    P_A = a * g * a.inv()
    #Bob的私钥b
    b = generate_weak_private_key(g,60)
    #Bob的公钥P_B
    P_B = b * g * b.inv()

    #Alice计算出的共享密钥
    K_Alice = a * P_B * a.inv()
    #Bob计算出的共享密钥
    K_Bob = b * P_A * b.inv()

    print(f'Alice和Bob的共享密钥是否相等: {K_Alice==K_Bob}')
    print(f'Alice的共享密钥: {K_Alice}')

if __name__ == "__main__":
    main()
```

其实做的时候挺迷糊的,exp 后面整理一下再写

### 天虫的秘密

task.py

```python

from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES
from secret import FLAG
import base64
import os

KEY=os.urandom(16)
iv1=os.urandom(16)
cipher=AES.new(KEY,AES.MODE_CBC,iv=iv1)
ct=cipher.encrypt(pad(FLAG,16))
print(base64.b64encode(iv1+ct))

def oracle(data_b64: bytes) -> bytes:
    try:
        data = base64.b64decode(data_b64.strip())
        if len(data) < 32 or len(data) % 16 != 0:
            return b'ERR1\n'
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        try:
            unpad(pt, 16)
            return b'OK\n'
        except ValueError:
            return b'ERR2\n'
    except Exception:
        return b'ERR3\n'


while True:
    tries=input("Enter what you want to try, format: base64(iv+ct)\n")
    if tries=="q":
        break
    else:
        print(oracle(tries))
```

aes 攻击罢了

exp.py

```python
import socket, base64, re, sys, time

HOST =
PORT =
BLOCK = 16

def recv_all_banner(sock):
    buf = b""
    sock.settimeout(10)
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"Enter what you want to try" in buf or b"try, format" in buf:
                break
        except socket.timeout:
            break
    return buf

def extract_iv_ct(banner_bytes):
    m = re.search(rb"b'([A-Za-z0-9+/=]+)'", banner_bytes)
    if not m:
        m = re.search(rb"([A-Za-z0-9+/=]{32,}={0,2})", banner_bytes)
    if not m:
        print("[-] 未找到初始密文的 base64 串。原始输出：")
        print(banner_bytes.decode(errors="ignore"))
        sys.exit(1)
    raw = base64.b64decode(m.group(1))
    if len(raw) < 32 or len(raw) % 16 != 0:
        print("[-] 初始密文长度异常。")
        sys.exit(1)
    return raw[:BLOCK], [raw[i:i+BLOCK] for i in range(BLOCK, len(raw), BLOCK)]

def recv_until_result(sock, deadline_s=60):
    end = time.monotonic() + deadline_s
    buf = b""
    sock.settimeout(5)  # 单次 recv 最多等 5s，但整体等到 deadline
    while time.monotonic() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("连接被对端关闭")
            buf += chunk
            if b"OK" in buf:
                return "OK"
            if b"ERR1" in buf:
                return "ERR1"
            if b"ERR2" in buf:
                return "ERR2"
            if b"ERR3" in buf:
                return "ERR3"
        except socket.timeout:
            continue
    raise TimeoutError("等待服务返回超时")

def oracle(sock, payload_bytes, pause=0.01):
    b64 = base64.b64encode(payload_bytes) + b"\n"
    sock.sendall(b64)
    res = recv_until_result(sock)
    if pause:
        time.sleep(pause)
    return res == "OK"

def decrypt_block(sock, prev_block, block):
    S = [0] * BLOCK
    P = bytearray(BLOCK)
    for pad in range(1, BLOCK+1):  # pad = 1..16
        i = BLOCK - pad
        found = None

        base = bytearray(prev_block)
        for j in range(i+1, BLOCK):
            base[j] = S[j] ^ pad

        for g in range(256):
            iv_try = bytearray(base)
            iv_try[i] = g
            if oracle(sock, bytes(iv_try) + block):
                if pad == 1:
                    iv_try2 = bytearray(iv_try)
                    iv_try2[0] ^= 1
                    if not oracle(sock, bytes(iv_try2) + block):
                        found = g
                        break
                    cand = g
                    iv_try3 = bytearray(iv_try)
                    iv_try3[1] ^= 1
                    if not oracle(sock, bytes(iv_try3) + block):
                        found = g
                        break
                    found = cand
                else:
                    found = g
                    break

        if found is None:
            raise RuntimeError(f"未找到字节 {i} 的候选，可能被限流/断线。")

        S[i] = found ^ pad
        P[i] = S[i] ^ prev_block[i]
    return bytes(P)

def pkcs7_unpad(data):
    k = data[-1]
    if k < 1 or k > BLOCK or data[-k:] != bytes([k])*k:
        raise ValueError("bad pad")
    return data[:-k]

def main():
    with socket.create_connection((HOST, PORT)) as sock:
        banner = recv_all_banner(sock)
        sock.settimeout(None)   # 或 sock.settimeout(30)
        iv, cblocks = extract_iv_ct(banner)
        print(f"[+] 拿到 {1+len(cblocks)} 个块（含IV），开始爆破……")
        pt_blocks = []
        prev = iv
        for idx, cb in enumerate(cblocks, 1):
            print(f"[+] 解密第 {idx}/{len(cblocks)} 块……", flush=True)
            pt = decrypt_block(sock, prev, cb)
            pt_blocks.append(pt)
            prev = cb
        plaintext = b"".join(pt_blocks)
        try:
            m = pkcs7_unpad(plaintext)
        except Exception:
            m = plaintext
        print("\n==== Plaintext ====")
        try:
            print(m.decode("utf-8"))
        except UnicodeDecodeError:
            print(m)
        print("===================")
        try:
            sock.sendall(b"q\n")
        except Exception:
            pass

if __name__ == "__main__":
    main()
```

这里交互不太会写，大胆的丢给 ai

### 三重密钥锁

task.py

```python
import random
from Crypto.Util.number import *
# from sage.all import*


def encode_flag_to_abc(flag):

    flag_bytes = flag.encode()

    third = len(flag_bytes) // 3
    a_bytes = flag_bytes[:third]
    b_bytes = flag_bytes[third:2*third]
    c_bytes = flag_bytes[2*third:]

    a = bytes_to_long(a_bytes)
    b = bytes_to_long(b_bytes)
    c = bytes_to_long(c_bytes)

    return a, b, c



p = random_prime(2^512, lbound=2^511)
bitsize = 128


a, b, c = encode_flag_to_abc(flag)



assert a < 2^bitsize and b < 2^bitsize and c < 2^bitsize


k = random.randint(1, p-1)
m = random.randint(1, p-1)
n = random.randint(1, p-1)


f = (k * a + m * b + n * c) % p

print("=== 三重密钥锁（标量版）===")
print(f"模数 p = {p}")
print(f"系数 k = {k}")
print(f"系数 m = {m}")
print(f"系数 n = {n}")
print(f"验证值 f = {f}")
print(f"提示: a,b,c都是大约{bitsize}比特的整数")
```

也不知道叽叽咕咕说什么呢，LLL 秒了

exp.py

```python
from Crypto.Util.number import long_to_bytes

p =
k =
m =
n =
f =

inv_n = inverse_mod(n, p)

D = diagonal_matrix(ZZ, [2^128, 1, 2^32, 2^64])
L = Matrix(ZZ, [[1, 0, 0, f*inv_n % p],
                [0, 1, 0, k*inv_n % p],
                [0, 0, 1, m*inv_n % p],
                [0, 0, 0, p]]) * D

re = L.LLL()[0]
print(re)

print(long_to_bytes(re[1])+long_to_bytes(re[2])+long_to_bytes(abs(re[3])))
```

## 挑战题

### [Cry]置换 DLP

PDLP 问题，先分解置换 g，然后检查 h 在 c1 和 c2 上面的限制，然后解同余数方程组。这里直接喂给 ai 就出来了。

### 黑盒

首先交互

```
nc 8.147.132.32 23823
Matrix blackbox (stdin/stdout). Type HELP.
> help
Whats:
  A black box (function). After inputting a matrix, it outputs a matrix.
  All matrices are in GL(n,q).
Commands:
  QUERY <matrix>      -- get f(matrix)
  STAGE1              -- get Y = f(X_secret); then guess X_secret
  GUESS <matrix>      -- submit candidate X for stage1
  STAGE2              -- After you passed STAGE1 and figured out the structure of the black box,
                         you need to submit a very important matrix S. f(X) is related to S.
                         If you pass STAGE2, I will give you FLAG
  SOLVE <matrix>      -- submit candidate S (accepted up to nonzero scalar)
  HELP                -- this message
  QUIT                -- exit
Parameters:
  n                   -- 4
  q                   -- 12667571192190072239
  max_queries         -- 100
Matrix Input Demonstration:
  3x3 identity matrix -- 1,0,0;0,1,0;0,0,1
>
```

`QUERY`去输入矩阵获取 f(x)
`STAGE1`让你去猜 x_s 的
`GUESS`就是看你求得 x_s 一样不
`STAGE2`提交矩阵去确定格式，这个是最重要的
`SOLVE`提交 s

第一开始尝试输入了一堆矩阵去看看是什么样的，后面 ai 提醒我，说黑盒里面的变换是`共轭变换`，那么 s 是可逆矩阵，那我们先拿到数据

```
> STAGE1
STAGE1: Here is Y = f(X_secret):
4922741916819782452,11624636787544295919,4421757138886764922,6908300509569190753;9016702631747257200,7001973736506386676,2862271926822216154,6071048405573194212;4100388960142535811,11775952539048264232,130999518679200202,2262354709086032869;6939576433328135859,10080980284042369301,2656809591423903335,7011271018923728928
Now guess X_secret. You need send GUESS <matrix>

```

我们交上去几个简单的可逆矩阵先，那么就有

$$
Y_k=f(X_k)=SX_kS^{-1} \\
对于每个k \\
Y_kS-SX_k=0
$$

先看看提交了什么

```
> QUERY 0,1,0,0;1,0,0,0;0,0,1,0;0,0,0,1
4647500898068133568,8594849169025944686,1971847543046523127,4499934600398542341;10145408489074701205,4419856912246749423,2675619996260238019,12615243991611319104;10302251780941654090,12625373671877494862,6435165200851703881,9709772521961126140;11238174010066896175,10862019721399636569,10337052275436204872,9832619373213557608
> QUERY 0,0,0,1;1,0,0,0;0,1,0,0;0,0,1,0
11192628362358705220,5098020383086411160,5689417656550788858,5428645942867617171;3080775929601410325,11678718344284554351,4341739966806069784,489526636547706056;988047865571005826,8929691797518831025,2924012025470105058,5922076694416506581;10468259544846216519,9987394686629661584,3226867502806693309,12207354844456852088
> QUERY 1,0,0,0;0,2,0,0;0,0,3,0;0,0,0,4
5191709153753268221,6550531916874927317,6317336406912241808,2473574739429013923;5103620087494281912,11395010096245385366,10211837074685681124,9474847698661494414;4525382561950301335,2912637557735821227,6394064262066616413,12225341397875111279;11830655983051427715,5838853945895028458,467585891049658253,2354358872314874488
>
```

令 $S$ 为 $4 \times 4$ 矩阵，$\mathrm{vec}(S)$ 是 $16 \times 1$ 向量。根据 Kronecker 积的性质，我们有：

$$
\begin{align*}
\mathrm{vec}(Y_k S) &= (I \otimes Y_k) \mathrm{vec}(S) \\
\mathrm{vec}(S X_k) &= (X_k^T \otimes I) \mathrm{vec}(S)
\end{align*}
$$

由于 $Y_k S = S X_k$，因此我们得到齐次线性方程组：

$$
(I \otimes Y_k - X_k^T \otimes I) \mathrm{vec}(S) = 0
$$

其中 $A_k = I \otimes Y_k - X_k^T \otimes I$ 是一个 $16 \times 16$ 矩阵，且 $A_k \mathrm{vec}(S) = 0$。

那么我们对 A 进行高斯消元，求出 0 空间，然后求出 S 和 X

(PS:脚本不会写，grok 救我)

```python
import numpy as np

q = 12667571192190072239

def mod_inverse(a, m):
    return pow(a, m - 2, m)

def mat_mul(A, B, mod):
    return np.dot(A, B) % mod

def kron(A, B):
    return np.kron(A, B)

def mat_inv(M, mod):
    n = M.shape[0]
    augmented = np.hstack((M, np.eye(n, dtype=object)))
    for i in range(n):
        # Find pivot
        pivot = augmented[i, i]
        if pivot == 0:
            for k in range(i + 1, n):
                if augmented[k, i] != 0:
                    augmented[[i, k]] = augmented[[k, i]]
                    pivot = augmented[i, i]
                    break
            else:
                raise ValueError("Matrix is singular")
        inv_pivot = mod_inverse(pivot, mod)
        augmented[i] = (augmented[i] * inv_pivot) % mod
        for j in range(n):
            if i != j:
                factor = augmented[j, i]
                augmented[j] = (augmented[j] - factor * augmented[i]) % mod
    return augmented[:, n:]

def rref(A, mod):
    m, n = A.shape
    A = A.copy()
    lead = 0
    for r in range(m):
        if lead >= n:
            break
        i = r
        while A[i, lead] == 0:
            i += 1
            if i == m:
                i = r
                lead += 1
                if lead == n:
                    break
        A[[r, i]] = A[[i, r]]
        pivot = A[r, lead]
        inv_pivot = mod_inverse(pivot, mod)
        A[r] = (A[r] * inv_pivot) % mod
        for i in range(m):
            if i != r:
                factor = A[i, lead]
                A[i] = (A[i] - factor * A[r]) % mod
        lead += 1
    return A

def nullspace(A, mod):
    m, n = A.shape
    rref_A = rref(A, mod)
    rank = np.sum(np.any(rref_A != 0, axis=1))
    nullity = n - rank
    if nullity != 1:
        raise ValueError(f"Nullity is {nullity}, expected 1")
    # Find free variables
    free_vars = []
    row = 0
    for col in range(n):
        if row < m and np.any(rref_A[row, col] != 0):
            row += 1
        else:
            free_vars.append(col)
    # Assuming nullity=1, set free var to 1, solve back
    basis = np.zeros(n, dtype=object)
    basis[free_vars[0]] = 1
    for r in range(rank - 1, -1, -1):
        lead_col = np.nonzero(rref_A[r])[0][0]
        sum_terms = np.sum(rref_A[r, lead_col + 1:] * basis[lead_col + 1:]) % mod
        basis[lead_col] = (-sum_terms * mod_inverse(rref_A[r, lead_col], mod)) % mod
    return basis

Y = np.array([
    [4922741916819782452, 11624636787544295919, 4421757138886764922, 6908300509569190753],
    [9016702631747257200, 7001973736506386676, 2862271926822216154, 6071048405573194212],
    [4100388960142535811, 11775952539048264232, 130999518679200202, 2262354709086032869],
    [6939576433328135859, 10080980284042369301, 2656809591423903335, 7011271018923728928]
], dtype=object) % q

# X1 and Y1
X1 = np.array([
    [0, 1, 0, 0],
    [1, 0, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1]
], dtype=object)
Y1 = np.array([
    [4647500898068133568, 8594849169025944686, 1971847543046523127, 4499934600398542341],
    [10145408489074701205, 4419856912246749423, 2675619996260238019, 12615243991611319104],
    [10302251780941654090, 12625373671877494862, 6435165200851703881, 9709772521961126140],
    [11238174010066896175, 10862019721399636569, 10337052275436204872, 9832619373213557608]
], dtype=object) % q

# X2 and Y2
X2 = np.array([
    [0, 0, 0, 1],
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0]
], dtype=object)
Y2 = np.array([
    [11192628362358705220, 5098020383086411160, 5689417656550788858, 5428645942867617171],
    [3080775929601410325, 11678718344284554351, 4341739966806069784, 489526636547706056],
    [988047865571005826, 8929691797518831025, 2924012025470105058, 5922076694416506581],
    [10468259544846216519, 9987394686629661584, 3226867502806693309, 12207354844456852088]
], dtype=object) % q

# X3 and Y3
X3 = np.array([
    [1, 0, 0, 0],
    [0, 2, 0, 0],
    [0, 0, 3, 0],
    [0, 0, 0, 4]
], dtype=object)
Y3 = np.array([
    [5191709153753268221, 6550531916874927317, 6317336406912241808, 2473574739429013923],
    [5103620087494281912, 11395010096245385366, 10211837074685681124, 9474847698661494414],
    [4525382561950301335, 2912637557735821227, 6394064262066616413, 12225341397875111279],
    [11830655983051427715, 5838853945895028458, 467585891049658253, 2354358872314874488]
], dtype=object) % q

pairs = [(X1, Y1), (X2, Y2), (X3, Y3)]

I = np.eye(4, dtype=object)

A_blocks = []
for X_k, Y_k in pairs:
    A_k = kron(I, Y_k) - kron(X_k.T, I)
    A_k %= q
    A_blocks.append(A_k)

A = np.vstack(A_blocks) % q

vec_S = nullspace(A, q)

last_elem = vec_S[-1]
if last_elem != 0:
    inv_last = mod_inverse(last_elem, q)
    vec_S = (vec_S * inv_last) % q
else:
    pass

S = np.zeros((4,4), dtype=object)
for j in range(4):
    for i in range(4):
        S[i,j] = vec_S[i + j*4]

S_inv = mat_inv(S, q)

X_secret = mat_mul(mat_mul(S_inv, Y, q), S, q)

def print_matrix(M):
    return ';'.join([','.join(map(str, row)) for row in M])

print("S:")
print(print_matrix(S))
print("\nX_secret:")
print(print_matrix(X_secret))

```

### [Cry]运气与实力

呃，上面的升级版，靠运气吗，有点难，打表循环太少了，几乎不可能，这里直接逆出来 ab，然后预测，这次 ai 启动

exp.py

```python
import re
import time
from math import gcd

from pwn import remote

M = 2 ** 24
HOST = "39.106.48.123"
PORT =

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x1, y1, g = egcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)

def solve_linear_congruence(A, B, MOD):
    g = gcd(A, MOD)
    if B % g != 0:
        return None
    A2 = A // g
    B2 = B // g
    MOD2 = MOD // g
    inv, _, _ = egcd(A2, MOD2)
    inv %= MOD2
    x0 = (inv * (B2 % MOD2)) % MOD2
    return x0

def ask(io, x):
    io.sendline(f"{x} {x}".encode())
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            line = io.recvline(timeout=1).decode(errors='ignore').strip()
        except Exception:
            line = ""
        if not line:
            continue
        nums = re.findall(r"\b\d+\b", line)
        if len(nums) >= 1:
            return int(nums[0]) % M
    raise Exception("从服务器读取 Hash(x) 超时或没找到数字")

def recover_abc_from_queries(io):
    h0 = ask(io, 0)
    h1 = ask(io, 1)
    h2 = ask(io, 2)
    c = h0 % M
    s1 = (h1 - h0) % M
    s2 = (h2 - h0) % M
    a_calc = ((s2 - 2 * s1) // 2) % M
    b_calc = (s1 - a_calc) % M
    return a_calc, b_calc, c

def find_collision_local(a, b):
    for r in range(24):
        t = 1 << r
        MOD = 1 << (24 - r)
        A = (2 * a) % MOD
        B = (-a * t - b) % MOD
        sol = solve_linear_congruence(A, B, MOD)
        if sol is None:
            continue
        x2 = sol
        x1 = (x2 + t) % M
        if x1 == x2:
            continue
        h1 = (a * (x1 * x1 % M) + b * x1) % M
        h2 = (a * (x2 * x2 % M) + b * x2) % M
        if h1 == h2:
            return x1, x2
    return None

def main():
    io = remote(HOST, PORT, timeout=8)
    welcome = b""
    try:
        welcome = io.recvuntil(b"Input Format: x1 x2\n", timeout=3)
    except Exception:
        pass
    welcome_text = welcome.decode(errors='ignore')
    nums = re.findall(r"\b\d+\b", welcome_text)
    if len(nums) >= 3:
        a_remote = int(nums[0]) % M
        b_remote = int(nums[1]) % M
        c_remote = int(nums[2]) % M
    else:
        try:
            a_remote, b_remote, c_remote = recover_abc_from_queries(io)
        except Exception as e:
            io.close()
            return

    res = find_collision_local(a_remote, b_remote)
    if res is None:
        io.close()
        return
    x1, x2 = res

    io.sendline(f"{x1} {x2}".encode())

    try:
        out = b""
        out += io.recvline(timeout=2)
        try:
            out += io.recvall(timeout=2)
        except Exception:
            pass
        out_text = out.decode(errors='ignore')
    except Exception:
        out_text = "(读取返回超时或失败)"
    print(out_text)
    io.close()

if __name__ == "__main__":
    main()

```

### [Cry]随机数之旅 3.6

task.py

```python
# Sage 9.3
import random
import uuid

flag="flag{"+str(uuid.uuid4())+"}"

n=len(flag)
m=n-6
p=random_prime(2**64)

A=[random.randint(p//2,p-1) for _ in range(m*n)]
A=matrix(Zmod(p),m,n,A)

x=[ord(i) for i in flag]
x=vector(x)

b=A*x

with open("output.txt","w") as f:
    f.write(str(p)+"\n")
    f.write(str(list(A))+"\n")
    f.write(str(list(b)))

```

当时丢给 ai 一把梭了，就没怎么看

```python
from sage.all import *
from sage.modules.free_module_integer import IntegerLattice

with open("output.txt", "r") as f:
    p = int(f.readline().strip())
    A_list_str = f.readline().strip()
    b_list_str = f.readline().strip()

A_list = eval(A_list_str)
b_list = eval(b_list_str)

n = len(A_list[0])  #
m = len(A_list)

R = GF(p)
A = matrix(R, A_list)
b = vector(R, b_list)

pivots = A.pivots()
free_cols = sorted(set(range(n)) - set(pivots))
d = len(free_cols)

perm = list(pivots) + free_cols

A_perm = A[:, perm]

A_left = A_perm[:, :m]
A_right = A_perm[:, m:]

inv_left = A_left.inverse()

C = inv_left * A_right

C_int = matrix(ZZ, m, d, [int(C[i, j]) for i in range(m) for j in range(d)])

x_piv_part = inv_left * b
x_part_perm = vector(ZZ, [int(x_piv_part[i]) for i in range(m)] + [0] * d)

B = matrix(ZZ, n, n)

for k in range(d):
    col = vector(ZZ, n)
    for i in range(m):
        col[i] = -C_int[i, k]
    col[m + k] = 1
    B[:, k] = col

for l in range(m):
    col = vector(ZZ, n)
    col[l] = p
    B[:, d + l] = col

target = vector(ZZ, [-xi for xi in x_part_perm])

Lat = IntegerLattice(B.transpose())

v_closest = Lat.approximate_closest_vector(target, algorithm='embedding')

x_sol_perm = x_part_perm + v_closest

x_sol = vector(ZZ, [0] * n)
for k in range(n):
    x_sol[perm[k]] = x_sol_perm[k]

print(x_sol)

valid_bytes = all(0 <= xi <= 127 for xi in x_sol)
print(f"All entries valid ASCII bytes: {valid_bytes}")

# Recover flag
flag = ''.join(chr(int(xi)) for xi in x_sol)
print(f"Recovered flag: {flag}")

A_zz = matrix(ZZ, A_list)
x_zz = vector(ZZ, x_sol)
b_zz = vector(ZZ, b_list)
computed = (A_zz * x_zz) % p
print(f"Verification (computed b == original b): {list(computed) == b_list}")

```

### [Cry]随机数之旅 3.9

task.py

```python
# Sage 9.3
import random
import uuid
from Crypto.Util.number import bytes_to_long as b2l

flag="flag{"+str(uuid.uuid4())+"_"+str(uuid.uuid4())+"_"+str(uuid.uuid4())+"}"
mes=b2l(flag.encode())

n=30
m=500
p=random_prime(2**64);print("p=",p)

ec=[random.randint(1,p-1) for _ in range(2)]
e=[random.choice(ec) for _ in range(m)]
e=vector(e)

A=[random.randint(1,p-1) for _ in range(m*n)]
A=matrix(Zmod(p),m,n,A)
x=vector([random.randint(1,2**32) for _ in range(n)])

b=A*x+e

print("A=",list(A))
print("ec=",ec)
print("b=",list(b))

key=prod(x[i] for i in range(n))
print("c=",mes^^key)
```

这里是上一题的升级版，第一眼看上去像是 lwe，但是一直 LLL 出不来，换成出题人的解方程思路试试.

e 只能二选一，那么对于每一行，必有一个二次方程成立

$(A_i*x-(b_i-ec_0))*(A_i*x-(b_i-ec_1))=0 \mod p$

那么就有五百个这样的方程，把二次项当作新的独立变量，就有 465 个，加上 30 个原来的，就是 495 个，超定线性方程组启动。

```python
from Crypto.Util.number import long_to_bytes
from sage.all import *

p=
ec=
A_list=
b_list=
c=

n = 30
m = 500
F = Zmod(p)
A = matrix(F, m, n, A_list)
b = vector(F, b_list)
ec = vector(F, ec)

num_vars = n + n * (n + 1) // 2

monomial_to_index = {}
for i in range(n):
    monomial_to_index[(i,)] = i
idx = n
for i in range(n):
    for j in range(i, n):
        monomial_to_index[(i, j)] = idx
        idx += 1

M = matrix(F, m, num_vars)
V = vector(F, m)

for i in range(m):
    V[i] = -(b[i] - ec[0]) * (b[i] - ec[1])

    L_term_coeff = - ( (b[i]-ec[0]) + (b[i]-ec[1]) )
    for j in range(n):
        idx = monomial_to_index[(j,)]
        M[i, idx] = L_term_coeff * A[i, j]

    for j in range(n):
        for k in range(j, n):
            idx = monomial_to_index[(j, k)]
            if j == k:
                M[i, idx] += A[i, j]**2
            else:
                M[i, idx] += 2 * A[i, j] * A[i, k]

sol = M.solve_right(V)
x_recovered = vector(F, [sol[i] for i in range(n)])

x_int = [int(v) for v in x_recovered]

key = 1
for val in x_int:
    key *= val

mes = c ^ key
flag = long_to_bytes(mes)

print("\nFlag: {}".format(flag.decode()))
```

### [Cry]weil 的噪声与秩序

task.py

```python
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from sage.all import *
from functools import reduce
from random import*


def mul(numbers):
    return reduce(lambda x, y: x * y, numbers)

res = []


p = res[10]
pp = mul(res)
K = GF(p)
E = EllipticCurve(K, (0, 4))

o=2^2*3^2*12739*41023*212743486005970872224021162564581383306228707471162349947823799966605796835340989758720027890521598136441
b=[]
for char in flag:
    a = bin(char)[2:].zfill(8)
    for i in a:
        b.append(i)


c=[]
for l in b:
    print(l)
    if l=='1':
        P = (o//2//2)*E.random_element()
        Q = (o//2//2)*E.random_element()
        d=P.weil_pairing(Q, 2)*getrandbits(381)
        c.append(d)
    else:
        P = (o//3//3)*E.random_element()
        Q = (o//3//3)*E.random_element()
        d=P.weil_pairing(Q, 3)
        c.append(d)

with open('c.py','w') as file:
    file.write(f'{c=}')

```

这个就是简单的配对，判断 01 即可

exp.py

```python
res = []

p = res[10]

try:
    with open('c.py', 'r') as file:
        exec(file.read())
except FileNotFoundError:
    exit(1)
except Exception:
    exit(1)

bits = ''
for i, d in enumerate(c):
    d_mod = d % p
    if pow(d_mod, 3, p) == 1:
        bit = '0'
    else:
        bit = '1'
    bits += bit

flag = ''
bit_length = len(bits)
if bit_length % 8 != 0:
    bits += '0' * (8 - bit_length % 8)

for i in range(0, len(bits), 8):
    byte_bin = bits[i:i+8]
    char_code = int(byte_bin, 2)
    char = chr(char_code)
    flag += char

print(f"{flag}")
```
