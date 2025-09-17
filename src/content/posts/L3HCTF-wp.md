---
title: L3HCTF Wp
published: 2025-07-15
pinned: false
description: L3HCTF，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-07-15
pubDate: 2025-07-15
---


## 前言

密码这次真的简单吧xd，当作记录帖子了

## 题目

### math_problem

task.py

```python
import gmpy2
from gmpy2 import *
from Crypto.Util.number import *
from random import randint
from gmpy2 import invert
from scret import flag

def myfunction(num):
    output = 0
    output=num**3
    return output

if __name__ == '__main__':
    flag_len = len(flag)
    p, q = getPrime(512), getPrime(512)

    while True:
        r = getPrime(512)
        R = bytes_to_long(str(r).encode())
        if isPrime(R):
            break

    n = p * q * r
    hint1 = R * r
    mod = myfunction(n)
    hint2 = pow(3*n+1, p % (2 ** 400), mod)
    m = bytes_to_long(flag)
    c = pow(m, 65537, n)

    print('All data:')
    print(f'n = {n}')
    print(f'c = {c}')
    print(f'hint1 = {hint1}')
    print(f'hint2 = {hint2}')
```

#### 非预期

GCD把r求出来，然后直接求解

```python
n = 
c = 
hint1 = 
hint2 = 

from Crypto.Util.number import *
r=GCD(hint1,n)

print(long_to_bytes(pow(c,inverse(65537,r-1),r)))
```

#### 预期解

p这里在hint2可以通过二项式定理求出低位

$$
hint_2=1+p_l*3n+\frac{p_l(p_l-1)}{2}(3n)^2 \mod n^3\\
hint_2=1+p_l*3n \mod n^2 \\
p_l=\frac{hint_2 \mod n^2 -1}{3n}
$$

然后打copper就行了

```python
from sage.all import*
from Crypto.Util.number import *

n = 
c = 
hint1 = 
hint2 = 

r = GCD(n, hint1)
pl = (hint2 % (n^2) - 1) // (3 * n)
R.<x> = Zmod(n//r)[]
f = x * 2^400 + pl
f = f.monic()

ph = f.small_roots(X=2^112, beta=0.4)[0]

p = ZZ(ph * 2^400 + pl)
q = n // (p * r)

phi = (p - 1) * (q - 1) * (r - 1)

d = inverse(65537, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

### EzECDSA

task.py

```python
import hashlib
import random
from ecdsa import NIST256p, SigningKey

class FlawedNonceGenerator:
    def __init__(self, n):
        self.n = n
        self.a = random.randrange(1, n)
        self.b = random.randrange(1, n)
        self.c = random.randrange(1, n)
        self.last_k = random.randrange(1, n)

    def generate_nonce(self):
        current_k = self.last_k
        next_k = (self.a * current_k**2 + self.b * current_k + self.c) % self.n
        self.last_k = next_k
        
        return current_k


curve = NIST256p
n = curve.order
private_key = SigningKey.from_secret_exponent(random.randrange(1, n), curve=curve)
d = private_key.privkey.secret_multiplier
public_key = private_key.get_verifying_key()

messages = [
    b"Hello player, welcome to L3HCTF 2025!",
    b"This is a crypto challenge, as you can probably tell.",
    b"It's about ECDSA, a very... robust algorithm.",
    b"I'm sure there are no implementation flaws whatsoever.",
    b"Anyway, here are your signatures. Good luck!",
    f"Oh, and the flag is L3HCTF{{{d}}}. Don't tell anyone!".encode(),
]
nonce_generator = FlawedNonceGenerator(n)
f = open('signatures.txt', 'w')

for i in range(6):
    k = nonce_generator.generate_nonce()
    message = messages[i]
    h = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    R = k * curve.generator
    r = R.x() % n
    s_inv = pow(k, -1, n)
    s = (s_inv * (h + d * r)) % n
    f.write(f"h: {h}, r: {r}, s: {s}\n")
```

gemini可以一把梭，主要就是矩阵解一下？

```python
import hashlib

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
signatures_text = """

"""
lines = signatures_text.strip().split('\n')
signatures = []
for line in lines:
    parts = line.split(', ')
    h = Integer(parts[0].split(': ')[1])
    r = Integer(parts[1].split(': ')[1])
    s = Integer(parts[2].split(': ')[1])
    signatures.append({'h': h, 'r': r, 's': s})

R = GF(n)
P.<d> = PolynomialRing(R)
u_vals, v_vals = [], []
for sig in signatures[:5]:
    h, r, s = R(sig['h']), R(sig['r']), R(sig['s'])
    s_inv = s.inverse()
    u_vals.append(s_inv * h)
    v_vals.append(s_inv * r)

k = [u_vals[i] + v_vals[i] * d for i in range(5)]
M_data = [[k[i]**2, k[i], R(1), k[i+1]] for i in range(4)]
M = Matrix(P, M_data)
det_poly = M.determinant()
roots = det_poly.roots()
print(roots)
```

### RRRSSSAAA

task.sage

```python
from sage.all import *

from secret import flag

def generate_vulnerable_key(bits=1024):
    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = random_prime(2**(p_bits), lbound=2**(p_bits-1))
        q = random_prime(2**(q_bits), lbound=2**(q_bits-1))
        if p != q and p > q and p < 2*q:
            break
            
    N = p * q
    phi = (p**4 - 1) * (q**4 - 1)

    d_bits = 1024
    d_bound = 2**d_bits

    while True:
        d_small = randint(2, d_bound)
        d = phi - d_small
        if gcd(d, phi) == 1:
            if d_small.bit_length() == 1021:
                break

    e = inverse_mod(d, phi)
    
    return N, e

def encrypt(m, N, e):
    n = 4
    r = 2
    R = Integers(N)
    P = PolynomialRing(R, 't')
    t = P.gen()
    Q = P.quotient(t**n - r)

    m_poly = Q([m, 0, 0, 0])

    c_poly = m_poly ** e

    return c_poly.lift()

if __name__ == "__main__":
    N, e = generate_vulnerable_key()
    m = int.from_bytes(flag, 'big')
    c = encrypt(m, N, e)

    print(f"N = {N}")
    print(f"e = {e}")
    print(f"c = {c}")
```

打连分数求出d的xd，分母位长度是1021位，校验一下，然后爆破每一个d，然后转成flag判断头

```python
from sage.all import *
from Crypto.Util.number import *
N = 
e = 
c = 

nn = N**4

alpha = e / nn

cf = continued_fraction(alpha)
convergents = cf.convergents()

for conv in convergents:
    k_candidate = conv.numerator()
    d_small_candidate = conv.denominator()
    
    if d_small_candidate >= 2**1020 and d_small_candidate < 2**1021:
        try:
            c_inv = inverse(c, N)
            m = pow(c_inv, d_small_candidate, N)
            
            flag = long_to_bytes(m)
            
            if b'L3HCTF{' in flag:
                print("Flag found:", flag)
                break
        except:
            continue

else:
    print("fuck")
```

