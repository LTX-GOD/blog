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
