---
title: Seccon beginner 2025 Wp
published: 2025-07-27
pinned: false
description: Seccon beginner 2025 crypto wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-07-27
pubDate: 2025-07-27
---


## 整体概况

rank 135/880

感觉可以更高的，毕竟没有一直打，这次主要水了一下cry和re，下面是整体题目情况

```
## crypto

### seesaw (100pt / 612 solves)

### 01-Translator (100pt / 280 solves)

### Elliptic4b (272pt / 171 solves)

### Golden Ticket (491pt / 35 solves)

### mathmyth (452pt / 79 solves)

## reversing

### CrazyLazyProgram1 (100pt / 654 solves)

### CrazyLazyProgram2 (100pt / 468 solves)

### D-compile (100pt / 335 solves)

### wasm_S_exp (100pt / 330 solves)

### MAFC (339pt / 144 solves)

### code_injection (441pt / 88 solves)

```

加`*`号的是没出来的

## Crypto

### seesaw

task.py

```python
import os
from Crypto.Util.number import getPrime

FLAG = os.getenv("FLAG", "ctf4b{dummy_flag}").encode()
m = int.from_bytes(FLAG, 'big')

p = getPrime(512)   
q = getPrime(16)
n = p * q
e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")

```

分解后用p即可

```python
p =
n = 
c = 

from Crypto.Util.number import*

print(long_to_bytes(pow(c,inverse(65537,p-1),p)))
```

### 01-Translator

task.py

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long


def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), 16))

flag = os.environ.get("FLAG", "CTF{dummy_flag}")
flag_bin = f"{bytes_to_long(flag.encode()):b}"
trans_0 = input("translations for 0> ")
trans_1 = input("translations for 1> ")
flag_translated = flag_bin.translate(str.maketrans({"0": trans_0, "1": trans_1}))
key = os.urandom(16)
print("ct:", encrypt(flag_translated, key).hex())

```

一个很有意思的题目，把二进制里面的`0/1`替换掉，然后再`AES-ECB`加密。

主要解密的方法就是输入两个字符串，然后根据频率选出两块，分别尝试A->1,B->0/B->1,A->0，然后就可以解密成功了，这里脚本通过gemini编写

```python
from Crypto.Util.number import long_to_bytes

ct = ''
zero = ''
one = ''

ct = ''
zero = ''
one = ''

block_size = 32
blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]

bitstring = ''
for block in blocks:
    if block == one:
        bitstring += '1'
    elif block == zero:
        bitstring += '0'

num = int(bitstring, 2)
print(long_to_bytes(num))
```

### Elliptic4b

task.py

```python
import os
import secrets
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

flag = os.environ.get("FLAG", "CTF{dummy_flag}")
y = secrets.randbelow(secp256k1.p)
print(f"{y = }")
x = int(input("x = "))
if not secp256k1.is_point_on_curve((x, y)):
    print("// Not on curve!")
    exit(1)
a = int(input("a = "))
P = Point(x, y, secp256k1)
Q = a * P
if a < 0:
    print("// a must be non-negative!")
    exit(1)
if P.x != Q.x:
    print("// x-coordinates do not match!")
    exit(1)
if P.y == Q.y:
    print("// P and Q are the same point!")
    exit(1)
print("flag =", flag)
```

这个ECC题目就很就简单了，题目生成了一个y值，我们要输入一个x并且确保在曲线上，然后输入a，并且满足后面的条件

解密方法很简单。你首先要知道`secp256k1`曲线的方程是`y² = x³ + 7  (mod p)`，x可以直接求出，后面就是ECC的常识`(q−1)⋅P=−P`，那么a就出来了

```python
import sympy
from pwn import remote
from fastecdsa.curve import secp256k1

p = secp256k1.p
q = secp256k1.q

while True:
    try:
        io = remote('elliptic4b.challenges.beginners.seccon.jp', 9999)
        io.recvuntil(b'y = ')
        y = int(io.recvline().strip())
        print(f"[*] Received y = {y}")
        c = (y * y - 7) % p
        x = sympy.nthroot_mod(c, 3, p, all_roots=False)
        io.sendlineafter(b'x = ', str(x).encode())
        print("[*] Sent x.")

        a = q - 1
        io.sendlineafter(b'a = ', str(a).encode())
        print("[*] Sent a.")
        
        # 4. 接收 flag 并退出循环
        print("\n[+] Success! Flag:")
        response = io.recvall(timeout=2)
        print(response.decode())
        io.close()
        break

    except Exception as e:
        print(f"[!] An error occurred: {e}. Retrying...")
        if 'io' in locals() and io:
            io.close()
```

### mathmyth

task.py

```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long
import os, hashlib, secrets


def next_prime(n: int) -> int:
    n += 1
    while not isPrime(n):
        n += 1
    return n


def g(q: int, salt: int) -> int:
    q_bytes = q.to_bytes((q.bit_length() + 7) // 8, "big")
    salt_bytes = salt.to_bytes(16, "big")
    h = hashlib.sha512(q_bytes + salt_bytes).digest()
    return int.from_bytes(h, "big")


BITS_q = 280
salt = secrets.randbits(128)

r = 1
for _ in range(4):
    r *= getPrime(56)

for attempt in range(1000):
    q = getPrime(BITS_q)
    cand = q * q * next_prime(r) + g(q, salt) * r
    if isPrime(cand):
        p = cand
        break
else:
    raise RuntimeError("Failed to find suitable prime p")

n = p * q

e = 0x10001
d = pow(e, -1, (p - 1) * (q - 1))

flag = os.getenv("FLAG", "ctf4b{dummy_flag}").encode()
c = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"r = {r}")

```

一个有趣的数学题。

$$
n=p*q=q^3*rr+g*q*r \\
n=q^3*rr \mod r
$$

r是四个素数相乘，自然而然crt，`q = t+kr`是不能求出的，后面发现直接硬爆，假设g那一块为0，我们可以轻易的求出q，那么随着k的下降，g的值就会上升，g大约在512bits一下，那么爆破的次数就是几百次。很好的一种方法

```python
from sage.all import*
from Crypto.Util.number import*
n = 
e = 65537
c = 
r = 

def solve(n, e, c, r, max_steps=600):
    rp = next_prime(r)
    
    prime_factors_r = [p for p, _ in factor(r)]
    residues_per_prime = []
    
    for pi in prime_factors_r:
        Z_pi = IntegerModRing(pi)
        Ai = Z_pi(n) * Z_pi(rp)^-1
        roots = Ai.nth_root(3, all=True)
        residues_per_prime.append(list(map(int, roots)))

    # 使用 itertools.product 生成所有余数组合，然后用CRT求解
    from itertools import product
    t_list = [crt(list(res_combo), prime_factors_r) for res_combo in product(*residues_per_prime)]
    print(t_list)
    for t in t_list:
        Q0, _ = (n // rp).nth_root(3, truncate_mode=True)
        # q = t + k*r, 因此 k ≈ (Q0 - t) / r
        k0 = (Q0 - t) // r

        for k in range(k0, k0 - max_steps, -1):
            q_candidate = t + k * r
            
            if q_candidate <= 1 or not is_prime(q_candidate):
                continue

            num = n - q_candidate^3 * rp
            den = r * q_candidate
            
            if num > 0 and num % den == 0:
                S = num // den
                p_candidate = q_candidate^2 * rp + r * S
                
                if p_candidate * q_candidate == n and is_prime(p_candidate):
                    p, q = p_candidate, q_candidate
                    print(f"✅ 成功找到因子!")
                    print(f"  p = {p}")
                    print(f"  q = {q}")
                    
                    # 3. 解密
                    phi = (p - 1) * (q - 1)
                    d = inverse_mod(e, phi)
                    m = power_mod(c, d, n)
                    
                    return long_to_bytes(m)

    return None 
flag = solve(n, e, c, r)
print(flag)
```

#### copper的写法

最近`cuso`库公开了，可以用这个直接求，非常的nb

```python
from sage.all import *
from Crypto.Util.number import *
import cuso
import ast

n = 
e = 65537
c = 
r = 
a = next_prime(r) - r
for Q in Zmod(r)(n/a).nth_root(3, all=True):
    Q = int(Q)
    x, p = var("x, p")
    roots = cuso.find_small_roots(
        relations=[Q+x*r],
        bounds={x: (0, 2**59)},
        modulus_multiple=n,
        modulus_lower_bound=2**279,
        modulus_upper_bound=2**280
    )
    for root in roots:
        p = int(root[p])
        q = n // p
        print(long_to_bytes(pow(c, pow(e, -1, (p-1)*(q-1)), n)))
        break
```

### Golden Ticket(*)

task.py

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


flag = os.environ.get("FLAG", "ctf4b{dummy_flag}")
iv = os.urandom(16)
key = os.urandom(16)
challenge = os.urandom(16 * 6)
ENC_TICKET = 3
DEC_TICKET = 3
GOLDEN_TICKET = 0

def menu() -> int:
    print("Your tickets:")
    if ENC_TICKET > 0:
        print(f"{ENC_TICKET} encryption ticket(s)")
    if DEC_TICKET > 0:
        print(f"{DEC_TICKET} decryption ticket(s)")
    if GOLDEN_TICKET > 0:
        print(f"{GOLDEN_TICKET} golden ticket(s)")
    print()
    print(f"1. Encrypt")
    print(f"2. Decrypt")
    print(f"3. Get ticket")
    print(f"4. Get flag")
    print(f"5. Quit")
    while True:
        i = int(input("> "))
        if 1 <= i <= 5:
            return i
        print("Invalid input!")

def consume_ticket(enc: int = 0, dec: int = 0, golden: int = 0):
    global ENC_TICKET, DEC_TICKET, GOLDEN_TICKET
    if ENC_TICKET < enc or DEC_TICKET < dec or GOLDEN_TICKET < golden:
        print("Not enough tickets.")
        exit(1)
    ENC_TICKET -= enc
    DEC_TICKET -= dec
    GOLDEN_TICKET -= golden

while True:
    i = menu()

    if i == 1:
        consume_ticket(enc=1)
        pt = bytes.fromhex(input("pt> "))
        if len(pt) > 16:
            print("Input must not be longer than 16 bytes.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        print(f"ct:", cipher.encrypt(pad(pt, 16)).hex())

    if i == 2:
        consume_ticket(dec=1)
        ct = bytes.fromhex(input("ct> "))
        if len(ct) > 16:
            print("Input must not be longer than 16 bytes.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        print("pt:", cipher.decrypt(pad(ct, 16)).hex())

    if i == 3:
        print("challenge:", challenge.hex())
        answer = bytes.fromhex(input("answer> "))
        if len(answer) != len(challenge) + 16:
            print("Wrong length.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=answer[:16])
        if cipher.decrypt(answer[16:]) == challenge:
            print("Correct!")
            GOLDEN_TICKET += 1337
        else:
            print("Wrong :(")

    if i == 4:
        consume_ticket(golden=1)
        print("flag:", flag)

    if i == 5:
        print("Bye!")
        exit(0)
```

我对aes的了解还是太少了，需要补充一下这方面的知识了。

整个代码应该挺好阅读的吧

1. 选项一就是加密
2. 选项二就是解密
3. 选项三，服务器给一个challenge，我们传一个answer并且加密后要满足`AES-CBC-Decrypt(ciphertext, iv, key) == challenge`
4. 选项四得到flag

首先我们肯定要获取challenge的值，
然后我们要求出iv，求iv的方法老生常谈了，
我们输入`b"\x10"*16`，加密时会padding，也就是实际加密了`b"\x10"*32`，那么我们可以得到的是d1和d2，分别是`d1 = xor(encrypt(b"\x10"*16), iv)`、`d2 = xor(encrypt(b"\x10"*16), b"\x10"*16)`，这里xor就可以求出iv
那么前面几段可以通过xor求出来
后面的部分通过encrypt就可以推出来

```python
import os
from pwn import *

sc = remote("golden-ticket.challenges.beginners.seccon.jp", 9999)

def enc_oracle(pt):
    sc.recvuntil(b"> ")
    sc.sendline(b"1")
    sc.recvuntil(b"> ")
    sc.sendline(pt.hex().encode())
    sc.recvuntil(b": ")
    return bytes.fromhex(sc.recvline().decode())

def dec_oracle(pt):
    sc.recvuntil(b"> ")
    sc.sendline(b"2")
    sc.recvuntil(b"> ")
    sc.sendline(pt.hex().encode())
    sc.recvuntil(b": ")
    return bytes.fromhex(sc.recvline().decode())

def get_ticket(answer):
    sc.recvuntil(b"> ")
    sc.sendline(b"3")
    sc.recvuntil(b": ")
    challenge = bytes.fromhex(sc.recvline().decode())
    sc.recvuntil(b"> ")
    sc.sendline(answer.hex().encode())
    sc.recvline()
    return challenge

chal = get_ticket(b"a")
chal = [chal[i:i+16] for i in range(0, len(chal), 16)]

f3 = b"\x10"*16
d = dec_oracle(f3)
print(d)
iv = xor(b"\x10"*16, d[:16], d[16:])
f2 = xor(f3, d[16:], chal[2])
f1 = xor(dec_oracle(f2)[:16], iv, chal[1])
f0 = xor(dec_oracle(f1)[:16], iv, chal[0])
f4 = enc_oracle(xor(f3, iv, chal[3]))[:16]
f5 = enc_oracle(xor(f4, iv, chal[4]))[:16]
f6 = enc_oracle(xor(f5, iv, chal[5]))[:16]

get_ticket(f0+f1+f2+f3+f4+f5+f6)

sc.recvuntil(b"> ")
sc.sendline(b"4")
print(sc.recvline().decode())
```

## 总结

seccon beginner的题还是一如既往的又新又好
