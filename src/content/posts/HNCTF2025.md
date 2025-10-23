---
title: HNCTF2025
published: 2025-06-08
pinned: false
description: HNCTF2025，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-08
pubDate: 2025-06-08
---


## 前言
rank18 我是fw

## 题目

### 哈基coke
task.py
```python

import matplotlib.pyplot as plt
import cv2
import numpy as np
from PIL import Image
def arnold_encode(image, shuffle_times, a, b):
    """ Arnold shuffle for rgb image
    Args:
        image: input original rgb image
        shuffle_times: how many times to shuffle
    Returns:
        Arnold encode image
    """
    arnold_image = np.zeros(shape=image.shape)

    h, w = image.shape[0], image.shape[1]
    N = h

    for time in range(shuffle_times):
        for ori_x in range(h):
            for ori_y in range(w):

                new_x = (1*ori_x + b*ori_y)% N
                new_y = (a*ori_x + (a*b+1)*ori_y) % N

                arnold_image[new_x, new_y, :] = image[ori_x, ori_y, :]

        image = np.copy(arnold_image)

    cv2.imwrite('en_flag.png', arnold_image, [int(cv2.IMWRITE_PNG_COMPRESSION), 0])
    return arnold_image

img = cv2.imread('coke.png')
arnold_encode(img,6,9,1)
```
Arnold变换，我不是特别懂原理的，gpt一把梭了

exp.py
```python
import cv2
import numpy as np

def arnold_decode(image, shuffle_times, a, b):
    """ Arnold inverse shuffle for RGB image
    Args:
        image: input encoded RGB image
        shuffle_times: how many times it was shuffled
    Returns:
        Decoded image
    """
    h, w = image.shape[:2]
    N = h
    arnold_image = np.zeros_like(image)

    # 逆Arnold变换矩阵
    for time in range(shuffle_times):
        for x in range(h):
            for y in range(w):
                ori_x = ((b * a + 1) * x - b * y) % N
                ori_y = (-a * x + y) % N
                arnold_image[ori_x, ori_y, :] = image[x, y, :]

        image = np.copy(arnold_image)

    cv2.imwrite('decoded_flag.png', arnold_image, [int(cv2.IMWRITE_PNG_COMPRESSION), 0])
    return arnold_image

# 解密主逻辑
encoded_img = cv2.imread('en_flag.png')
decoded_img = arnold_decode(encoded_img, 6, 9, 1)
```

### lcgp
task.py
```python
from Crypto.Util.number import *
import gmpy2
import random
import uuid
n = getPrime(1024)
flag = b'H&NCTF{' + str(uuid.uuid4()).encode() + b'}'
flag=bytes_to_long(flag)
print(flag)
e = 2024
c=pow(e, flag, n)

class LCG:
    def __init__(self, seed, a, b, m):
        self.seed = seed
        self.a = a
        self.b = b
        self.m = m

    def generate(self):
        self.seed = (self.a * self.seed + self.b) % self.m
        return self.seed

lcg = LCG(c, getPrime(256), getPrime(256), getPrime(2048))
random = [lcg.generate() for _ in range(5)]

print(random)
print("n=",n)
```
前面就是很正常的LCG解密，然后是个简单的dlp问题，就不多说了

exp.py
```python
from math import gcd
from functools import reduce
from Crypto.Util.number import inverse

def recover_modulus(states):
    diffs = [s2 - s1 for s1, s2 in zip(states, states[1:])]
    zeroes = []
    for i in range(len(diffs) - 2):
        x = diffs[i + 2] * diffs[i] - diffs[i + 1] ** 2
        zeroes.append(abs(x))
    return reduce(gcd, zeroes)

def recover_lcg_params(states, m):
    s0, s1, s2 = states[:3]
    a = ((s2 - s1) * inverse(s1 - s0, m)) % m
    b = (s1 - a * s0) % m
    return a, b

def recover_seed(states, a, b, m):
    s1 = states[0]
    seed = ((s1 - b) * inverse(a, m)) % m
    return seed

states = [
]

m = recover_modulus(states)
a, b = recover_lcg_params(states, m)

c = recover_seed(states, a, b, m)
print("[*] Recovered c =", c)
from Crypto.Util.number import long_to_bytes
from sage.all import *
n=
cc=
e = 2024
F = GF(n)
g = F(2024)
c = F(cc)
flag_int = discrete_log(c, g) 
print(flag_int)
print(long_to_bytes(flag_int))
```

### 数据处理
task.py
```python
from Crypto.Util.number import bytes_to_long
import random
flag = b"H&NCTF{}"

btl = str(bytes_to_long(flag))
lowercase = '0123456789' 
uppercase = '7***4****5' 

table = ''.maketrans(lowercase, uppercase) 

new_flag = btl.translate(table)
n = 2 ** 512

m = random.randint(2, n - 1) | 1


c = pow(m, int(new_flag), n)
print('m = ' + str(m))
print('c = ' + str(c))
```

前面dlp，后面爆破

exp.py
```python
from Crypto.Util.number import long_to_bytes
from sage.all import *
m = 
cc = 
n = 2 ** 512

flag_int = discrete_log(cc, mod(m,n))
print(flag_int)

from itertools import permutations
from Crypto.Util.number import long_to_bytes

new_flag = ''

known_map = {
    '7': '0',
    '4': '4',
    '5': '9'
}

used_digits = {'0', '4', '9'}
available_digits = [d for d in '0123456789' if d not in used_digits]

unknown_chars = sorted(set(new_flag) - set(known_map.keys()))

for perm in permutations(available_digits):
    full_map = dict(known_map)
    for ch, digit in zip(unknown_chars, perm):
        full_map[ch] = digit
    
    try:
        btl = ''.join(full_map[ch] for ch in new_flag)
        num = int(btl)
        flag = long_to_bytes(num)
        if flag.startswith(b'H&NCTF{'):
            print("[+] 找到啦！")
            print("映射表：", full_map)
            print("flag:", flag)
            break
    except:
        continue
```

### 为什么出题人的rsa总是ez
task.py
```python
#part 1

def pad(flag, bits=1024):
    pad = os.urandom(bits//8 - len(flag))
    return int.from_bytes(flag + pad, "big")

p = random_prime(2**1024)
q = random_prime(2**1024)
a = randint(0, 2**1024)
b = randint(0, 2**1024)
n = p * q
e = 0x10001
flag = b''
m = pad(flag)
assert m < n

c = pow(m, e, n)

print(f"c={c}")
print(f"n={n}")
print(f"h1={p + b * q}")
print(f"h2={a * p + q}")

#part 2

from Crypto.Util.number import *
from gmpy2 import *
a = random_prime()
b = random_prime()
g = random_prime()
h = 2*g*a*b+a+b
while not is_prime(h):
    a = random_prime()
    b = random_prime()
    g = random_prime()
    h = 2*g*a*b+a+b
N = 2*h*g+1
e from part1's flag
flag=b''
c=pow(bytes_to_long(flag),e,N)
print(N)
print(g)
print(c)
```

前面是[maple](https://blog.maple3142.net/2024/05/28/angstromctf-2024-writeups/)神的博客的脚本，直接梭哈，part2就是强网那个，以前的脚本改改还能用

exp.py
```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from lll_cvp import solve_inequality


c=
n=
x=
y=

# f(t,u)=(x-t)(y-u)
# f(p,q)=0 (mod n)
# f(t,u)=xy-ux-ty+tu=xy-ux-ty (mod n)
# x, y ~ 2^1024 -> LLL

L = matrix([[n, 0, 0, 0], [x * y, 1, 0, 0], [-y, 0, 1, 0], [-x, 0, 0, 1]])
lb = [0, 1, 0, 0]
ub = [0, 1, 2**1024, 2**1024]
sol = solve_inequality(L, lb, ub)

_, _, p, q = map(int, sol)
assert p * q == n
phi = (p - 1) * (q - 1)
d = pow(0x10001, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))

N=
g=
from sage.groups.generic import bsgs
nbits = 2048
gamma = 0.244
cbits = ceil(nbits * (0.5 - 2 * gamma))

M = (N - 1) // (2 * g)
u = M // (2 * g)
v = M - 2 * g * u
GF = Zmod(N)
x = GF.random_element()
y = x ^ (2 * g)
# c的范围大概与N^(0.5-2*gamma)很接近
c = bsgs(y, y ^ u, ((2**(cbits-5)), (2**(cbits+5))))
ab = u - c
apb = v + 2 * g * c
P.<x> = ZZ[]
f = x ^ 2 - apb * x + ab
a = f.roots()
if a:
    a, b = a[0][0], a[1][0]
    p = 2 * g * a + 1
    q = 2 * g * b + 1
    assert p * q == N
    print(p,q)

from Crypto.Util.number import*
c=
p=
q=
e=81733668723981020451323
n=

phi=(p-1)*(q-1)
print(pow(c,inverse(e,phi),n))
print(long_to_bytes(pow(c,inverse(e,phi),n)))
```

### factor
task.py
```python
from Crypto.Util.number import *
import uuid

rbits = 248
Nbits = 1024

p = getPrime(Nbits // 2)
q = getPrime(Nbits // 2) 
N = p * q
r = getPrime(rbits)
hint = getPrime(Nbits // 2) * p + r
R = 2^rbits
e=0x10001
n=p*q
phi=(p-1)*(q-1)
flag = b'H&NCTF{' + str(uuid.uuid4()).encode() + b'}'
m=bytes_to_long(flag)
c=pow(m,e,n)
print("N=",N)
print("hint=",hint)
print(c)
```

我是真的nmd不能理解啊我靠，写的时候第一时间想到copper去打，一直出不来，然后最后发现可能是参数写错了？md，xd废了  
r是小量，利用copper打出来，然后GCD求p，即可求出flag，`small_roots`里面的`epsilon`一定要加上啊啊啊啊啊啊

exp.py
```python
from Crypto.Util.number import*
from sage.all import *

N= 
hint= 
c=

e=65537
rbits = 248
Nbits = 1024
R = 2^rbits

PR.<x> = PolynomialRing(Zmod(N))
f=x-hint
roots=f.small_roots(X=2^248,beta=0.4,epsilon=0.01)
r=roots[0]
print(r)

r=
p=GCD(hint-r,N)
q=N//p
phi=(p-1)*(q-1)
print(long_to_bytes(pow(c,inverse(e,phi),N)))
```

还有一个方法就是AGCD，参考[鸡块神的博客](https://tangcuxiaojikuai.xyz/post/4a67318c.html#12)，但是限度大概在243bits左右，需要爆破5位

### factor-pro
task.py
```python
from Crypto.Util.number import *
from Crypto.Util.Padding import *
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
from hashlib import sha256
from random import *
import uuid
rbits = 252
Nbits = 1024

p = getPrime(Nbits//2)
q = getPrime(Nbits//2)
N = p*q
r = getPrime(rbits)
hint = getPrime(Nbits// 2)*p+r
R = 2^rbits
flag = b'H&NCTF{'+str(uuid.uuid4()).encode()+b'}'
leak=p*q*r
r_bytes = long_to_bytes(leak)
iv = r_bytes[:16] if len(r_bytes) >= 16 else r_bytes + b'\0'*(16-len(r_bytes))
key = sha256(str(p + q + r).encode()).digest()[:16] 
crypt_sm4 = CryptSM4()
crypt_sm4.set_key(key, SM4_ENCRYPT)
padded_flag = pad(flag, 16)
c = crypt_sm4.crypt_cbc(iv, padded_flag)
print("N=",N)
print("hint=",hint)
print(c)
```

简单来说就是把上一题复杂化了，看到r变成了252bits，爆破几位就行了，md，又是没带参数，我是sb，实测最低必须爆12bits  

exp.py
```python
from Crypto.Util.number import*
from sage.all import *
from tqdm import*
N = 
hint = 

rbits = 252
Nbits = 1024
R = 2^rbits

high=12

for r in trange(2^high,-1,-1):
    rh=r<<(rbits-high)
    PR.<x> = PolynomialRing(Zmod(N))
    f=hint-(rh+x)
    f=f.monic()
    roots=f.small_roots(X=2^(rbits-high)-1,beta=0.495,epsilon=0.03)
    if roots:
        rl=roots[0]
        print(rh+rl)
        break
```

### three vertical lines
task.py
```python
from Crypto.Util.number import *
from secret import flag
from rsa.prime import getprime
while(1):
    p=getprime(256)
    q=getprime(256)
    if isPrime(3*p**5+4*q**5):
        print(3*p**5+4*q**5)
        break

e = 65537
print(pow(bytes_to_long(flag), e, p * q))
```
俺不会啊，赛后知道这个是原题改的，md，参考[love](https://lov2.netlify.app/nitectf-2024-tuan-dui-writeup/#r-stands-alone)的博客，原题有非预期，这个题貌似没有，当时试过（），打格就行了，这种构造的方法我还真的没有想出来，好nb

exp.py
```python
from sage.all import Zmod, ZZ, matrix, inverse_mod, GF
from functools import reduce
import Crypto.Util.number as cun

r=
ct=

e = 65537

# adwa solution

R = Zmod(r)["x"]
x = R.gen()
f = 3*x**5 + 4
root = f.roots()[0][0]
M = matrix(ZZ, [[1, root], [0, r]])

# by adwa:
# 似乎 ax^n + by^n, 都可以用格解决
# f = x ** 7 - 7
# e = f.roots()[0][0]
# 压力来到了 roots 函数, (其实就是个有限域求根)

b, a = map(abs, M.LLL()[0])
b, a = [int(i) for i in [a, b]]
print(f"a = {a}\nb = {b}")
print(f"{cun.isPrime(a) = }, {cun.isPrime(b) = }")

phi =(a-1)*(b-1)
n = a * b 
d = cun.inverse(e, phi)
m = pow(ct, d, n)
print(f"{m = }")
print(cun.long_to_bytes((m)))
```

## 总结
自己有点sb，不知道为什么，md