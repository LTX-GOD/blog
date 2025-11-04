---
title: 山东省鹏云杯线下决赛crypto-wp
published: 2025-10-26
pubDate: 2025-10-26
description: 山东省鹏云杯线下决赛 crypto wp
pinned: false
tags: ["crypto"]
category: CTF-crypto
author: zsm
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

密码题的分怎么这么少？look my eyes!

## 题目

### 你一定很懂 md5

task.py

```python
import uuid
import hashlib

flag = "flag{XXX}"

def abcduuid(flag):

    for char in flag:
        md5_hash = hashlib.md5(char.encode('utf-8')).hexdigest()
        print(f"{md5_hash}")

if __name__ == "__main__":
    abcduuid(flag)
```

随便爆破

```python
import hashlib

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`'

hash_to_char = {}
for char in chars:
    md5_hash = hashlib.md5(char.encode()).hexdigest()
    hash_to_char[md5_hash] = char

hashes=[]

flag = ''.join(hash_to_char.get(h, '?') for h in hashes)
print("恢复的 flag =", flag)
```

### 光滑

task.py

```python
from Crypto.Util.number import *
from random import choice
from secret import flag

flag=flag.decode('utf-8')+ "1" * 30
def getMyPrime(nbits):
    while True:
        p = 1
        while p.bit_length() <= nbits:
            p *= choice(sieve_base)

        if isPrime(p-1):
            return p-1

p = getMyPrime(256)
q = getMyPrime(256)

n = p*q
e = 65537
m = bytes_to_long(flag.encode('utf-8'))

c = pow(m, e, n)

print(f'n = {n}')
print(f'e = {e}')
print(f'c = {c}')
```

p+1 光滑

exp.py

```python
from Crypto.Util.number import inverse, long_to_bytes

n = 628367984743024460258949874461149142010669513982134034370937872907905412845791373384712099210680007304553638206133651385921799225422417075701557994891635322641
e = 65537
c = 463865728618910033824119037781408268137675300311981183906046145489848078253770973845564931794701097695379503336925847137631988673327885373164114472241504247048
p=453934123611868315924584320396524007218781226845135310539625979436424296065501477
assert n%p==0
q=n//p
m=pow(c,inverse(65537,(p-1)*(q-1)),n)
print(m)
flag=long_to_bytes(m)
print(flag)
for i in range(2**20):
    mm=m+i*n
    if b'flag{' in long_to_bytes(mm):
        print(long_to_bytes(mm))
'''
import math
from itertools import count

from gmpy2 import *


def primegen():
    yield 2
    for odd in count(3, 2):
        if all(odd % p > 0 for p in primes[:int(math.sqrt(odd))]):
            yield odd

primes = [2]
def ilog(x, p):
    """ Computes the integer logarithm of x to the base p. """
    # This function calculates how many times we need to divide x by p
    e = 0
    while x >= p:
        x //= p
        e += 1
    return e
def mlucas(v, a, n):
    """ Helper function for williams_pp1().  Multiplies along a Lucas sequence modulo n. """
    v1, v2 = v, (v**2 - 2) % n
    for bit in bin(a)[3:]:
        v1, v2 = ((v1**2 - 2) % n, (v1*v2 - v) % n) if bit == "0" else ((v1*v2 - v) % n, (v2**2 - 2) % n)
    return v1

for v in count(1):
    for p in primegen():
        e = ilog(isqrt(n), p)
        if e == 0:
            break
        for _ in range(e):
            v = mlucas(v, p, n)
        g = gcd(v-2, n)
        if 1 < g < n:
            print(g)
        if g == n:
            break

'''
```

### 罗宾

task.py

```python
from crypto.util.number import *
from secret import flag

while true:
    p = getprime(512)
    q = getprime(512)

    if p > q and p % 4 == 3 and q % 4 == 3:
        break

assert p > q
assert p % 4 == 3 and q % 4 == 3
n = p*q
e = 256
m = bytes_to_long(flag)
num1 = (pow(p,e,n)-pow(q,e,n)) % n
num2 = pow(p-q,e,n)
c = pow(m,e,n)

print("num1=",num1)
print("num2=",num2)
print("n=",n)
print("c=",c)
```

rabin+数论，num1+num2 就和 n 有 gcd 了

exp.py

```python
from Crypto.Util.number import *

tmp=num1+num2
p=GCD(tmp,n)
print(p)
q=n//p

inv_p = inverse(p, q)
inv_q = inverse(q, p)

cs = [c]
for i in range(8):
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
```

### ez_crypto

task.py

```python
#!/usr/bin/env python3
import os
import secrets
import random
from typing import List, Tuple

from secret import FLAG

def _miller_rabin_witness(a: int, d: int, n: int, s: int) -> bool:
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def is_probable_prime(n: int, rounds: int = 64) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        if _miller_rabin_witness(a, d, n, s):
            return False
    return True


def random_odd_bits(bits: int) -> int:
    x = secrets.randbits(bits) | 1
    x |= (1 << (bits - 1))
    return x


def get_prime(bits: int) -> int:
    while True:
        n = random_odd_bits(bits)
        if is_probable_prime(n):
            return n


R_BITS = 190
Q_BITS = 215
G_BITS = 128
P_BITS = 170
K_BITS = 16

NUM_CAL_FRAMES = 5


def encode_payload(payload_byte: int, base: int, key: int, modulus: int) -> int:
    return (payload_byte * pow(base, key, modulus)) % modulus


def build_frames(flag_bytes: bytes) -> Tuple[int, int, List[Tuple[str, int]]]:
    modulus = get_prime(P_BITS)
    base = get_prime(G_BITS)
    frame_scale = get_prime(Q_BITS)

    epoch_key = secrets.randbits(K_BITS)

    frames: List[Tuple[str, int]] = []

    for _ in range(NUM_CAL_FRAMES):
        bin_id = get_prime(R_BITS)
        codeword = frame_scale * bin_id + encode_payload(1, base, epoch_key, modulus)
        frames.append(("CAL", codeword))

    for b in flag_bytes:
        bin_id = get_prime(R_BITS)
        codeword = frame_scale * bin_id + encode_payload(b, base, epoch_key, modulus)
        frames.append(("DATA", codeword))

    return modulus, base, frames


def main() -> None:
    p, g, frames = build_frames(FLAG)

    banner = (
        "# Telemetry Aggregation Report\n"
        "# - Aggregator bins sensor frames into coarse buckets (FRAME_SCALE)\n"
        "# - Each frame carries a 1-byte payload, calibrated by an ephemeral EPOCH_KEY\n"
        "# - The calibration uses modular arithmetic against a system MODULUS and BASE\n"
        "#\n"
        "# Field notes: CAL frames are health-check beacons; DATA frames are actual readings.\n"
        "# Your task: reconstruct the DATA payload stream.\n"
    )

    with open("output.txt", "w") as f:
        f.write(banner)
        f.write(f"p = {p}\n")
        f.write(f"g = {g}\n")
        f.write(f"frames = {len(frames)}\n")
        for idx, (kind, cw) in enumerate(frames):
            f.write(f"frame[{idx}]: type={kind}, codeword={cw}\n")

    print("Challenge written to output.txt")


if __name__ == "__main__":
    main()
```

看构建的方法

> cw = frame*scale * bin*id + encode_payload(payload_byte, base, key, modulus)
> cw = q * r + (b \* h % p)

直接变形`cw % q = (b * h % p) % q = b * h % p`，使`m = cw % q = b * h % p`，那么 b 可以直接逆元了。

cal 中 b=1，那么所有的都相同了，`cw1 - cw2 = q * (r1 - r2) + (m_cal - m_cal) = q * (r1 - r2)`，GCD 启动！然后爆破 flag

exp.py

```python
from math import gcd
from typing import List, Tuple


def mod_inverse(a: int, m: int) -> int:
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    g, x, _ = extended_gcd(a, m)

    return (x % m + m) % m

p = 1059044419481232265210084377746088723503596941462371
g = 248096840098994800035575976902189528491

cal_cws = []

data_cws = []

def compute_frame_scale(cal_cws: List[int]) -> int:
    diffs = [abs(cal_cws[i] - cal_cws[0]) for i in range(1, len(cal_cws))]
    g = diffs[0]
    for d in diffs[1:]:
        g = gcd(g, d)

    q_cand = g // 2
    m_test = cal_cws[0] % q_cand
    consistent = all(cw % q_cand == m_test for cw in cal_cws)
    return q_cand

def main():
    q = compute_frame_scale(cal_cws)
    m_cal = cal_cws[0] % q

    h = m_cal % p
    inv_h = mod_inverse(h, p)
    flag_bytes = []
    for i, cw in enumerate(data_cws):
        m = cw % q
        b = (m * inv_h) % p
        flag_bytes.append(int(b))
    flag_str = ''.join(chr(b) for b in flag_bytes)
    print(flag_str)

if __name__ == "__main__":
    main()

```

### loss(\*)

task.py

```python
import gmpy2
from Crypto.Util.number import *
from secret import flag


p = getPrime(120)
q = getPrime(120)
n = p*q
phi = (p-1)*(q-1)
e = 65537
d = inverse(e, phi)
print("p =", p&((1<<70) - 1))

m = bytes_to_long(flag)
c = pow(m, e, n)
print(f'n = {n}')
print(f'c = {c}')


d = gmpy2.invert(e,(p-1)*(q-1))
c = pow(c, d, n)
print(long_to_bytes(c))

# p = 829064032203044318119
# n = 888793085913638480142106830358726592244023109092031700691387625262343693
# c = 523374243374032613886373469767323066972468234216292915827334155059267433
# b'T\x14\xae\xea\x0b*Z6\x92\x19\xe6\xc8\xde\x8f!T"\xb7[3\x9c\t\x92\x14Y\xe4\xa3\x8a\xd4\xe4'
```

pq 可以直接分解，但是直接求 rsa 不对，需要爆破？比赛爆了两个小时没出来 xd。可能是`m>>>n`导致的，
