---
title: 四月训练赛crypto-wp
published: 2026-04-28
pubDate: 2026-04-28
description: zsm Q1uju crypto wp
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false 
licenseName: "MIT"
lang: 'zh_CN'
---

## 前言

赛况惨烈，就一个有解，我服了

## 题目

### easy_sign

task.py

```python
from Crypto.Util.number import *
from flag import flag, msg
from gmpy2 import *

# msg中是加密flag的e
msg = msg + b"0" * 20


def gen_key(p, q):
    public_key = p * p * q
    e = public_key
    n = p * q
    phi_n = (p - 1) * (q - 1)
    private_key = inverse(e, phi_n)
    return public_key, private_key, e


p1 = getPrime(512)
q1 = getPrime(512)

N1, d1, e1 = gen_key(p1, q1)

c1 = pow(bytes_to_long(msg), e1, N1)

print("N1=", N1)
print("d1=", d1)
print("c1=", c1)


p2 = getPrime(128)
q2 = getPrime(128)

c2 = pow(bytes_to_long(flag), e, p2 * q2)
C = p2**2 + q2**2


print("c2=", c2)
print("C=", C)
```

首先看源码，很明显的两部分
第一部分是$$n=p^2*q,e=n$$,你需要知道这是Schmidt-Samoa密码系统


![image](./attachments/260428-102739.avif)

第二部分就更好玩了，$$C = p^2 + q^2$$,如果你有sagemath，会想到分解

但是求c却不对，这是因为这是多解问题，你可以用https://www.alpertron.com.ar/QUAD.HTM 进行计算，可以求到对的解，

也可以用sage的二元二次丢番图方程求解，进行分解

exp.py

```python
N1 = 
d1 = 
c1 = 


from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes
from gmpy2 import *

pq = gcd(pow(2, d1 * N1, N1) - 2, N1)

m = pow(c1, d1, pq)
print(long_to_bytes(m))

#e = 44519

c = 
C = 

import gmpy2
from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes
from gmpy2 import *
from sympy.abc import t, x, y
from sympy.solvers.diophantine.diophantine import diop_quadratic

e = 44519
"""
f = ZZ[I](C)
divisors_f = divisors(f)
for d in divisors_f:
    a,b = d.real(), d.imag()
    if a**2 + b**2 == C:
        p = abs(int(a))
        q = abs(int(b))
        if is_prime(p) and is_prime(q):
            print(p)
            print(q)
            break
"""

p = 
q = 

assert C == pow(p, 2) + pow(q, 2)
n = p * q
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)

for i in range(0, 100000000000000):
    mm = m + i * n
    flagg = long_to_bytes(mm)
    if b"flag{" in flagg:
        print(flagg)
```

### babybaby

task.py

```python
from Crypto.Util.number import *
from flag import flag

m = bytes_to_long(flag)
p = getStrongPrime(1024)
q = getStrongPrime(1024)
phi = (p - 1) * (q - 1)
e1 = inverse(getPrime(768), phi)
e2 = inverse(getPrime(768), phi)
e3 = inverse(getPrime(768), phi)
n = p * q
c = pow(m, 0x10001, n)
print(f"e1={e1}")
print(f"e2={e2}")
print(f"e3={e3}")
print(f"c={c}")
print(f"n={n}")
```

其实就是3个e的维纳拓展攻击，参数都没改的

exp.py

```python
from Crypto.Util.number import*
e1=
e2=
e3=
c=
n=

L = matrix(ZZ, [
    [1, -n, 0, n**2, 0, 0, 0, -n**3],
    [0, e1, -e1, -n * e1, -e1, 0, n * e1, n**2 * e1],
    [0, 0, e2, -n * e2, 0, n * e2, 0, n**2 * e2],
    [0, 0, 0, e1 * e2, 0, -e1 * e2, -e1 * e2, -n * e1 * e2],
    [0, 0, 0, 0, e3, -n * e3, -n * e3, n**2 * e3],
    [0, 0, 0, 0, 0, e1 * e3, 0, -n * e1 * e3],
    [0, 0, 0, 0, 0, 0, e2 * e3, -n * e2 * e3],
    [0, 0, 0, 0, 0, 0, 0, e1 * e2 * e3]
])
# alpha = 768 / 2048
alpha = 2 / 5
D = diagonal_matrix(ZZ, [floor(pow(n, 3 / 2)), n, floor(pow(n, alpha + 3/2)), floor(pow(n, 1/2)), floor(pow(n, alpha + 3/2)), floor(pow(n, alpha + 1)), floor(pow(n, alpha + 1)), 1])
M = L * D
B = M.LLL()
b = vector(ZZ, B[0])
A = b * M^(-1)
phi = floor(A[1] / A[0] * e1)

d = inverse_mod(0x10001, phi)
m = pow(c, d, n)
flag = long_to_bytes(int(m))
print(flag)
```

### easy_Matrix

task.py

```python
import hashlib
import random

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes
from Crypto.Util.Padding import pad
from flag import *

p = getPrime(1024)


def f(x, c):
    r = 0
    for v in c:
        r = (r * x + v) % p
    return r


k = hashlib.sha256(flag).digest()
c = [bytes_to_long(k)]
for _ in range(29):
    c.append(bytes_to_long(hashlib.sha256(long_to_bytes(c[-1])).digest()))

pairs = [(x := random.randint(0, p), f(x, c)) for _ in range(20)]

iv = b"\x00" * 16
enc = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(flag, 16))

with open("out.txt", "w") as file:
    file.write(f"{p=}\n{pairs=}\n{(iv.hex(), enc.hex())=}\n")
```

欠定方程组，导致无法直接求解，那么肯定是格了xd

稍微处理一下，$$c_0 x_j^{n-1} + c_1 x_j^{n-2} + \dots + c_{n-1} x_j^0 - k_j p = y_j$$

搞成矩阵

$$
M = \left(
\begin{array}{c|c|c}
I_{n \times n} & W \cdot X & 0 \\ \hline
0 & W \cdot p I_{m \times m} & 0 \\ \hline
0 & -W \cdot Y & K
\end{array}
\right)
$$

那么LLL之后$$v = [c_0, c_1, \dots, c_{n-1}, \underbrace{0, 0, \dots, 0}_{m \text{ zeros}}, K]$$

exp.py

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad

p=
pairs=[]
enc_flag=('00000000000000000000000000000000', '9c7264cf50c67bcbb0ee97de74c8430cf4a1047c6372ce9db22b8e53c2422db3b674ca44a25fec5b8b9adc526dd9a6c1')

m = len(pairs)
n = 30 

W = 2^512
K = 2^255 

M = matrix(ZZ, n + m + 1, n + m + 1)

for k in range(n):
    M[k, k] = 1
    for j in range(m):
        M[k, n + j] = W * power_mod(pairs[j][0], n - 1 - k, p)

for j in range(m):
    M[n + j, n + j] = W * p

for j in range(m):
    M[n + m, n + j] = -W * pairs[j][1]
M[n + m, n + m] = K

reduced = M.LLL()

c0 = None
for row in reduced:
    if row[n+m] == K or row[n+m] == -K:
        sign = 1 if row[n+m] == K else -1
        c0 = int(row[0] * sign)
        break

if c0 is not None:
    MASTER_KEY = long_to_bytes(c0).rjust(32, b'\x00')

    iv = bytes.fromhex(enc_flag[0])
    enc = bytes.fromhex(enc_flag[1])
    cipher = AES.new(MASTER_KEY, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(enc), 16)
    print("Flag:", flag.decode())
else:
    print("未能在格内找到符合条件的最短向量。")
```

### Ez_Cu

`task.py`：

```python
from secret import flag
from Crypto.Util.number import getPrime, bytes_to_long

m = bytes_to_long(flag)
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537
c = pow(m, e, n)
ph = p >> 600
gift = (p % (2 ** 592)) % bytes_to_long(b'The CopperSmith\'s Gift')
print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(f"{ph = }")
print(f"{gift = }")

```

之前自己学校的比赛出过一模一样的，但是当时我们没有禁 AI，所以大家做的都还挺理想的，这题新生赛里也许是中等偏上？

`small_roots()`不深究原理使用的话就当成是一个模域下求解方程小根的函数工具就行。那么我们的目标就是通过给出的已知信息来建立一个方程等式来求出我们需要的小根信息。题目中给出了`ph`也就是`p`的高 424-bit，这肯定不足以直接打出`p`的剩下低 600-bit。

然后我们可以看看`gift`给出了什么：

```python
gift = (p % (2 ** 592)) % bytes_to_long(b'The CopperSmith\'s Gift')
```

也就是说`gift`是`p`的低 592-bit 模`bytes_to_long(b'The CopperSmith\'s Gift')`的余数，我们测试一下可知，大约是低 175-bit。

```python
from Crypto.Util.number import bytes_to_long

m = bytes_to_long(b'The CopperSmith\'s Gift')
print(m.bit_length(), m)
# 175 31580704707012293774603627903276951444456382271153780
```

现在来尝试把`p`用一个等式表达，中间缺失的 8-bit 我们用`pm`表示：
$$
p=ph*2^{600}+pm*2^{592}+k*m+gift
$$
整理一下信息，`ph`已知，`pm`仅 8-bit，`m`和`gift`已知，`k`大约`592 - 175 = 417`bit，可以直接爆破`pm`并用`CopperSmith`打出`k`，这样`p`就出来了。

`exp.py`：

```python
import sys
from tqdm import trange
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse

n = 
e = 65537
c = 
ph = 
gift = 
mod_ = bytes_to_long(b'The CopperSmith\'s Gift')
p_high = ph << 600
PR.<x> = PolynomialRing(Zmod(n))
for p_mid in trange(2 ** 8):
    pp = p_high + (p_mid * 2 ** 592)
    f = pp + x * mod_ + gift
    roots = f.monic().small_roots(X=2**418, beta=0.4, epsilon=0.05)
    if roots:
        for r in roots:
            p = int(pp + r * mod_ + gift)
            q = n // p
            assert p * q == n
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            m = pow(c, d, n)
            print(long_to_bytes(m).decode())
            sys.exit(1)
#  76%|█████████████████████████████████████████████████████████████▍                   | 194/256 [00:04<00:01, 47.53it/s]
# flag{I_th1nk_Y0u_4re_g00d_At_Copper}
```

### Prediction

`task.py`：

```python
import random
from secret import seed, flag
from Crypto.Util.number import bytes_to_long

flag = bytes_to_long(flag)
assert flag.bit_length() == 391
rng = random.Random()
rng.seed(seed)
nums = [rng.getrandbits(8) for _ in range(2496)]
key = rng.getrandbits(391)
enc = flag ^ key
with open("output.txt", "w") as f:
    f.write(f"nums = {str(nums)}\n")
    f.write(f"enc = {enc}")
```

ps：说实在的，相比于今年上半年以及去年下半年的一些比赛（包括新生赛）出的 MT19937 相关的题目来说，这道题真的太基础了。

当时考虑到禁 AI 的原因，就只略加了一点点难度（也许这题有个中等叭），把`randcrack`库给 ban 了，但是用`gf2bv`还是能很轻松地打出来，这里给个[老师傅的链接](https://mi1n9.github.io/2025/04/11/MT19937/#3-gf2bv)供大家学习，具体知识我就不细说了。

`exp.py`：

```python
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from tqdm import *
import random
from Crypto.Util.number import *

def mt19937(bs, out):
    lin = LinearSystem([32] * 624)
    mt = lin.gens()
    rng = MT19937(mt)
    zeros = [rng.getrandbits(bs) ^ o for o in out] + [mt[0] ^ 0x80000000]
    sol = lin.solve_one(zeros)
    rng = MT19937(sol)
    pyrand = rng.to_python_random()
    for i in range(2496):
        out.append(pyrand.getrandbits(8))
    return pyrand.getrandbits(391)

nums = [...]
enc = 
key = mt19937(8, nums)
print(long_to_bytes(key ^ enc).decode())
# flag{P3rh4ps_Cryptographers_4re_a11_G00D_Proph3t}
```

## 总结

其实并没有难为大家，更多的还是看看大家平时的积累，如果平时有刷题的话，应该能做出来前两个？
