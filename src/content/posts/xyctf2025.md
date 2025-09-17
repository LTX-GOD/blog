---
title: Xyctf2025
published: 2025-04-07
pinned: false
description: xyctf2025 wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-07
pubDate: 2025-04-07
---


## 前言
25年开始以来打的最高质量的密码了？

## 题目

### Division
抢了个血，怪不好意思的
task.py
```python
import random 
print('----Welcome to my division calc----')
print('''
menu:
      [1]  Division calc
      [2]  Get flag
''')
while True:
    choose = input(': >>> ')
    if choose == '1':
        try:
            denominator = int(input('input the denominator: >>> '))
        except:
            print('INPUT NUMBERS')
            continue
        nominator = random.getrandbits(32)
        if denominator == '0':
            print('NO YOU DONT')
            continue
        else:
            print(f'{nominator}//{denominator} = {nominator//denominator}')
    elif choose == '2':
        try:
            ans = input('input the answer: >>> ')
            rand1 = random.getrandbits(11000)
            rand2 = random.getrandbits(10000)
            correct_ans = rand1 // rand2
            if correct_ans == int(ans):
                print('WOW')
                with open('flag', 'r') as f:
                    print(f'Here is your flag: {f.read()}')
            else:
                print(f'NOPE, the correct answer is {correct_ans}')
        except:
            print('INPUT NUMBERS')
    else:
        print('Invalid choice')
```
第一时间拿到就知道是`mt19937`预测随机数，1里面输入1就可以拿到每次的随机数从而预测了
exp.py
```python
from pwn import remote
import random
from randcrack import RandCrack
rc = RandCrack()
conn = remote('8.147.132.32', 22975)
outputs = []

for _ in range(624):
    conn.recvuntil(b': >>> ')
    conn.sendline(b'1')
    conn.recvuntil(b'input the denominator: >>> ')
    conn.sendline(b'1')
    line = conn.recvline().decode().strip()
    nominator = int(line.split('=')[1].strip())
    outputs.append(nominator)
    rc.submit(nominator)


rand1 =rc.predict_getrandbits(11000)
rand2 = rc.predict_getrandbits(10000)
correct_ans = rand1 // rand2
print(correct_ans)
conn.recvuntil(b': >>> ')
conn.sendline(b'2')
conn.recvuntil(b'input the answer: >>>')
conn.sendline(correct_ans)
conn.interactive()
```

### Complex_signin
task.py
```python
from Crypto.Util.number import *
from Crypto.Cipher import ChaCha20
import hashlib
from secret import flag


class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im

    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)

    def __eq__(self, c):
        return self.re == c.re and self.im == c.im

    def __rshift__(self, m):
        return Complex(self.re >> m, self.im >> m)

    def __lshift__(self, m):
        return Complex(self.re << m, self.im << m)

    def __str__(self):
        if self.im == 0:
            return str(self.re)
        elif self.re == 0:
            if abs(self.im) == 1:
                return f"{'-' if self.im < 0 else ''}i"
            else:
                return f"{self.im}i"
        else:
            return f"{self.re} {'+' if self.im > 0 else '-'} {abs(self.im)}i"

    def tolist(self):
        return [self.re, self.im]


def complex_pow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = result * c
            result.re = result.re % n
            result.im = result.im % n
        c = c * c
        c.re = c.re % n
        c.im = c.im % n
        exp >>= 1
    return result

bits = 128
p = getPrime(1024)
q = getPrime(1024)
n = p * q
m = Complex(getRandomRange(1, n), getRandomRange(1, n))
e = 3
c = complex_pow(m, e, n)
print(f"n = {n}")
print(f"mh = {(m >> bits << bits).tolist()}")
print(f"C = {c.tolist()}")
print(f"enc = {ChaCha20.new(key=hashlib.sha256(str(m.re + m.im).encode()).digest(), nonce=b'Pr3d1ctmyxjj').encrypt(flag)}")
```

首先是个复数域的东西，然后是个m高位攻击，注意到复数域和实数域处理方法不一样
{{< raw >}}
$$
m=a+bi \\
m^e=(a+bi )^e=c \\
a^3+3a^2bi-3ab^2-b^3i=(a^3-3ab^2)+(3a^2b-b^3)i
$$
{{</ raw >}}
那么我们现在有了实部和虚部，`m>>bits`时可以类比于实部虚部一块位移，但是还是不能分开高位计算，那么就有了两个未知，`bits`是满足copper的，直接打就行了
exp.py
```python
import itertools
from Crypto.Util.number import *
from tqdm import *
def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m - i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

k =  128
n = 
mh = 
C = 

# 定义多项式环
PR.<x, y> = PolynomialRing(Zmod(n))

a = mh[0]  + x  # x 是 al
b = mh[1]  + y  # y 是 bl
f1 = (a^3 - 3*a*b^2) - C[0]  # 实部方程
f2 = (3*a^2*b - b^3) - C[1]  # 虚部方程
res = small_roots(f1,bounds=(2^128,2^128),m=1,d=3)
if res != []:
     print(res)

x=
y=

from Crypto.Cipher import ChaCha20
import hashlib

n = 
mh = 
enc = 
x=
y=
s = (mh[0]) + (mh[1])+x+y
key = hashlib.sha256(str(s).encode()).digest()
cipher = ChaCha20.new(key=key, nonce=b'Pr3d1ctmyxjj')
flag = cipher.decrypt(enc)
print(flag)
```

### 勒索病毒
拉下来发现是个exe，猜是python打包出来的，扔到https://pyinstxtractor-web.netlify.app 拆开，拿到pyc和pub.key和enc，然后pyc转py https://www.lddgo.net/string/pyc-compile-decompile

task.py
```python
# Visit https://www.lddgo.net/string/pyc-compile-decompile for more information
# Version : Python 3.8

'''
Created on Sun Mar 30 18:25:08 2025

@author: Crypto0

import re
import base64
import os
import sys
from gmssl import sm4
from Crypto.Util.Padding import pad
import binascii
from random import shuffle, randrange

N = 49 
p = 3
q = 128  
d = 3
assert q > (6 * d + 1) * p
R.<x> = ZZ[]
def generate_T(d1, d2):
    assert N >= d1 + d2
    s = [1] * d1 + [-1] * d2 + [0] * (N - d1 - d2)
    shuffle(s)
    return R(s)

def invert_mod_prime(f, p):
    Rp = R.change_ring(Integers(p)).quotient(x^N - 1)
    return R(lift(1 / Rp(f)))

def convolution(f, g):
    return (f * g) % (x^N - 1)

def lift_mod(f, q):
    return R([((f[i] + q // 2) % q) - q // 2 for i in range(N)])

def poly_mod(f, q):
    return R([f[i] % q for i in range(N)])

def invert_mod_pow2(f, q):
    assert q.is_power_of(2)
    g = invert_mod_prime(f, 2)
    while True:
        r = lift_mod(convolution(g, f), q)
        if r == 1:
            return g
        g = lift_mod(convolution(g, 2 - r), q)

def generate_message():
    return R([randrange(p) - 1 for _ in range(N)])

def generate_key():
    while True:
        try:
            f = generate_T(d + 1, d)
            g = generate_T(d, d)
            Fp = poly_mod(invert_mod_prime(f, p), p)
            Fq = poly_mod(invert_mod_pow2(f, q), q)
            break
        except:
            continue
    h = poly_mod(convolution(Fq, g), q)
    return h, (f, g)

def encrypt_message(m, h):
    e = lift_mod(p * convolution(h, generate_T(d, d)) + m, q)
    return e

def save_ntru_keys():
    h, secret = generate_key()
    with open("pub_key.txt", "w") as f:
        f.write(str(h))
    m = generate_message()
    with open("priv_key.txt", "w") as f:
        f.write(str(m))
    e = encrypt_message(m, h)
    with open("enc.txt", "w") as f:
        f.write(str(e))

def terms(poly_str):
    terms = []
    pattern = r\'([+-]?\\s*x\\^?\\d*|[-+]?\\s*\\d+)\'
    matches = re.finditer(pattern, poly_str.replace(\' \', \'\'))
    
    for match in matches:
        term = match.group()
        if term == \'+x\' or term == \'x\':
            terms.append(1)
        elif term == \'-x\':
            terms.append(-1)
        elif \'x^\' in term:
            coeff_part = term.split(\'x^\')[0]
            exponent = int(term.split(\'x^\')[1])
            if not coeff_part or coeff_part == \'+\':
                coeff = 1
            elif coeff_part == \'-\':
                coeff = -1
            else:
                coeff = int(coeff_part)
            terms.append(coeff * exponent)
        elif \'x\' in term:
            coeff_part = term.split(\'x\')[0]
            if not coeff_part or coeff_part == \'+\':
                terms.append(1)
            elif coeff_part == \'-\':
                terms.append(-1)
            else:
                terms.append(int(coeff_part))
        else:
            if term == \'+1\' or term == \'1\':
                terms.append(0)
                terms.append(-0)
    return terms

def gen_key(poly_terms):
    binary = [0] * 128
    for term in poly_terms:
        exponent = abs(term)
        if term > 0 and exponent <= 127:  
            binary[127 - exponent] = 1
    binary_str = \'\'.join(map(str, binary))
    hex_key = hex(int(binary_str, 2))[2:].upper().zfill(32)
    return hex_key

def read_polynomial_from_file(filename):
    with open(filename, \'r\') as file:
        return file.read().strip()


def sm4_encrypt(key, plaintext):
    assert len(key) == 16, "SM4 key must be 16 bytes"
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    padded_plaintext = pad(plaintext, 16)
    return cipher.crypt_ecb(padded_plaintext)

def sm4_encrypt_file(input_path, output_path, key):
    with open(input_path, \'rb\') as f:
        plaintext = f.read()
    
    ciphertext = sm4_encrypt(key, plaintext)
    
    with open(output_path, \'wb\') as f:
        f.write(ciphertext)

def resource_path(relative_path):
    if getattr(sys, \'frozen\', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def encrypt_directory(directory, sm4_key, extensions=[".txt"]):
    if not os.path.exists(directory):
        print(f"Directory does not exist: {directory}")
        return
    
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                input_path = os.path.join(root, file)
                output_path = input_path + ".enc"
                
                try:
                    sm4_encrypt_file(input_path, output_path, sm4_key)
                    os.remove(input_path)
                    print(f"Encrypted: {input_path} -> {output_path}")
                except Exception as e:
                    print(f"Error encrypting {input_path}: {str(e)}")

def main():
    try:
        save_ntru_keys()
        poly_str = read_polynomial_from_file("priv_key.txt")
        poly_terms = terms(poly_str)
        sm4_key = binascii.unhexlify(poly_terms)
        user_name = os.getlogin()
        target_dir = os.path.join("C:\\Users", user_name, "Desktop", "test_files")
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            print(f"Created directory: {target_dir}")
            return
            
        txt_files = [f for f in os.listdir(target_dir) 
                    if f.endswith(\'.txt\') and os.path.isfile(os.path.join(target_dir, f))]
        
        if not txt_files:
            print("No .txt files found in directory")
            return
            
        for txt_file in txt_files:
            file_path = os.path.join(target_dir, txt_file)
            try:
                with open(file_path, \'rb\') as f:
                    test_data = f.read()
                
                ciphertext = sm4_encrypt(sm4_key, test_data)
                encrypted_path = file_path + \'.enc\'
                
                with open(encrypted_path, \'wb\') as f:
                f.write(ciphertext)
            except Exception as e:
                print(f"Error processing {txt_file}: {str(e)}")
                
    except Exception as e:
        print(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main()
'''
```

enc.txt
```
e =
-x^48 - x^46 + x^45 + x^43 - x^42 + x^41 + x^40 + x^36 - x^35 + x^34 - x^33 + x^32 - x^30 + x^29 - x^28 - x^27 - x^26 - x^25 - x^23 - x^22 + x^21 + x^20 + x^19 + x^18 - x^17 - x^16 - x^15 - x^14 - x^12 + x^9 - x^7 - x^6 - x^5 - x^4 + x^3 - x + 1
```
pub_key.txt
```
h = 
```

其中enc里面的第二个多项式就是m
非预期exp.py
```python
import binascii
import re
from Crypto.Util.number import *
from gmssl import sm4

# 解析多项式字符串，提取每一项的次数 * 系数
def terms(poly_str):
    terms = []
    # 匹配 x^n、x、常数项等
    pattern = r'([+-]?x\^?\d*|[-+]?\d+)'
    matches = re.finditer(pattern, poly_str.replace(' ', ''))

    for match in matches:
        term = match.group()
        if term in ('+x', 'x'):
            terms.append(1)
        elif term == '-x':
            terms.append(-1)
        elif 'x^' in term:
            coeff_part, exponent = term.split('x^')
            exponent = int(exponent)
            if not coeff_part or coeff_part == '+':
                coeff = 1
            elif coeff_part == '-':
                coeff = -1
            else:
                coeff = int(coeff_part)
            terms.append(coeff * exponent)
        elif 'x' in term:
            coeff_part = term.split('x')[0]
            if not coeff_part or coeff_part == '+':
                terms.append(1)
            elif coeff_part == '-':
                terms.append(-1)
            else:
                terms.append(int(coeff_part))
        else:
            # 常数项 x^0，不影响密钥，但加入 0 是为了保留结构
            if term == '+1' or term == '1':
                terms.append(0)
            elif term == '-1':
                terms.append(-0)
    return terms

# 根据解析到的多项式项生成128位密钥（用于 SM4）
def gen_key(poly_terms):
    binary = [0] * 128
    for term in poly_terms:
        exponent = abs(term)
        if term > 0 and exponent <= 127:
            binary[127 - exponent] = 1  # 最高位是 x^127
    binary_str = ''.join(map(str, binary))
    hex_key = hex(int(binary_str, 2))[2:].upper().zfill(32)
    return binascii.unhexlify(hex_key)

# SM4 解密函数（ECB 模式）
def sm4_decrypt(key, ciphertext):
    assert len(key) == 16, "SM4 key must be 16 bytes"
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_DECRYPT)
    return cipher.crypt_ecb(ciphertext)

# 多项式字符串
poly_str = "-x^48-x^46+x^45+x^43-x^42+x^41+x^40+x^36-x^35+x^34-x^33+x^32-" \
           "x^30+x^29-x^28-x^27-x^26-x^25-x^23-x^22+x^21+x^20+x^19+x^18-" \
           "x^17-x^16-x^15-x^14-x^12+x^9-x^7-x^6-x^5-x^4+x^3-x+1"

# 提取多项式项
poly_terms = terms(poly_str)
print("多项式项：", poly_terms)

# 生成 SM4 密钥（16 字节）
sm4_key = gen_key(poly_terms)
print("SM4 密钥（hex）：", sm4_key.hex())

# 密文（注意这里原代码是 hex 字符串，需要转换成字节）
ciphertext_hex = (
    "bf0cb5cc6bea6146e9c1f109df953a57"
    "daa416d38a8ffba6438e7e599613e01f"
    "3b9a53dace4ccd55cd3e55ef88e0b835"
)
ciphertext = binascii.unhexlify(ciphertext_hex)

# 解密
plaintext = sm4_decrypt(sm4_key, ciphertext)
print("解密结果：", plaintext)

```

预期的话应该是求出m这个私钥，可以参考https://0xffff.one/d/1424/2

### reed
task.py
```python
import string
import random
from secret import flag

assert flag.startswith('XYCTF{') and flag.endswith('}')
flag = flag.rstrip('}').lstrip('XYCTF{')

table = string.ascii_letters + string.digits
assert all(i in table for i in flag)
r = random.Random()

class PRNG:
    def __init__(self, seed):
        self.a = 1145140
        self.b = 19198100
        random.seed(seed)

    def next(self):
        x = random.randint(self.a, self.b)
        random.seed(x ** 2 + 1)
        return x
    
    def round(self, k):
        for _ in range(k):
            x = self.next()
        return x

def encrypt(msg, a, b):
    c = [(a * table.index(m) + b) % 19198111 for m in msg]
    return c

seed = int(input('give me seed: '))
prng = PRNG(seed)
a = prng.round(r.randrange(2**16))
b = prng.round(r.randrange(2**16))
enc = encrypt(flag, a, b)
print(enc)
```

输入`seed`，然后产生$a*x+b \bmod p$，赛后听别的师傅说类似lcg，可以通过循环去限定ab的范围，然后排列组合爆破出来，啧，没想到，但是直接暴力匹配也可以

exp.py
```python
from string import ascii_letters, digits
import re
from typing import List, Tuple, Optional, Set

CHAR_TABLE = ascii_letters + digits
MOD = 19198111
ENC = []
def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a: int, m: int) -> Optional[int]:
    g, x, _ = extended_gcd(a, m)
    return x % m if g == 1 else None

def is_readable(s: str) -> bool:
    return bool(re.search(r'[A-Za-z]{2,}', s)) and len(re.findall(r'\d', s)) < 5

def solve() -> List[str]:
    candidates: Set[str] = set()
    processed: Set[Tuple[int, int]] = set()
    table_len = len(CHAR_TABLE)

    cipher_pairs = [(i, j) for i in range(len(ENC)) 
                   for j in range(i + 1, len(ENC)) if ENC[i] != ENC[j]]
    
    for idx1, idx2 in cipher_pairs:
        c1, c2 = ENC[idx1], ENC[idx2]
        delta_c = (c1 - c2) % MOD

        for i1 in range(table_len):
            p1 = ord(CHAR_TABLE[i1])
            for i2 in range(table_len):
                if i1 == i2:
                    continue
                p2 = ord(CHAR_TABLE[i2])
                
                delta_i = (p1 - p2) % MOD
                inv = modinv(delta_i, MOD)
                if inv is None:
                    continue
                    
                a = (delta_c * inv) % MOD
                b = (c1 - a * p1) % MOD
                
                if (a, b) in processed:
                    continue
                processed.add((a, b))

                a_inv = modinv(a, MOD)
                if a_inv is None:
                    continue
                    
                flag = []
                for c in ENC:
                    i = ((c - b) * a_inv) % MOD
                    if not (0 <= i < table_len):
                        break
                    flag.append(CHAR_TABLE[i])
                else: 
                    candidate = ''.join(flag)
                    if len(candidate) == len(ENC):
                        candidates.add(candidate)
    
    readable = [f for f in candidates if is_readable(f)]
    return readable if readable else list(candidates)

def main():
    results = solve()
    print(f"Found {len(results)} possible candidates:")
    for idx, flag in enumerate(results, 1):
        print(f"#{idx}: XYCTF{{{flag}}}")

if __name__ == "__main__":
    main()
```

### 复复复数
task.py
```python
class ComComplex:
    def __init__(self, value=[0,0,0,0]):
        self.value = value
    def __str__(self):
        s = str(self.value[0])
        for k,i in enumerate(self.value[1:]):
            if i >= 0:
                s += '+'
            s += str(i) +'ijk'[k]
        return s
    def __add__(self,x):
        return ComComplex([i+j for i,j in zip(self.value,x.value)])
    def __mul__(self,x):
        a = self.value[0]*x.value[0]-self.value[1]*x.value[1]-self.value[2]*x.value[2]-self.value[3]*x.value[3]
        b = self.value[0]*x.value[1]+self.value[1]*x.value[0]+self.value[2]*x.value[3]-self.value[3]*x.value[2]
        c = self.value[0]*x.value[2]-self.value[1]*x.value[3]+self.value[2]*x.value[0]+self.value[3]*x.value[1]
        d = self.value[0]*x.value[3]+self.value[1]*x.value[2]-self.value[2]*x.value[1]+self.value[3]*x.value[0]
        return ComComplex([a,b,c,d])
    def __mod__(self,x):
        return ComComplex([i % x for i in self.value])
    def __pow__(self, x, n=None):
        tmp = ComComplex(self.value)
        a = ComComplex([1,0,0,0])
        while x:
            if x & 1:
                a *= tmp
            tmp *= tmp
            if n:
                a %= n
                tmp %= n
            x >>= 1
        return a

from Crypto.Util.number import *
from secret import flag, hint

p = getPrime(256)
q = getPrime(256)
r = getPrime(256)
n = p * q * r

P = getPrime(512)
assert len(hint) == 20
hints = ComComplex([bytes_to_long(hint[i:i+5]) for i in range(0,20,5)])
keys = ComComplex([0, p, q, r])
print('hint =',hints)
print('gift =',hints*keys%P)
print('P =',P)

e = 65547
m = ComComplex([bytes_to_long(flag[i:i+len(flag)//4+1]) for i in range(0,len(flag),len(flag)//4+1)])
c = pow(m, e, n)
print('n =', n)
print('c =', c)
```

感觉ai比我懂，优先去回复pqr，代码定义的乘法就是四元数，那么就是三个线性同余式，可以直接去求解，让ai帮我搓个代码
```python
from Crypto.Util.number import long_to_bytes, inverse, bytes_to_long, getPrime
from sympy import Matrix
import sys

class ComComplex:
    def __init__(self, value=[0,0,0,0]):
        self.value = value
    def __str__(self):
        s = str(self.value[0])
        for k,i in enumerate(self.value[1:]):
            if i >= 0:
                s += '+'
            s += str(i) +'ijk'[k]
        return s
    def __add__(self,x):
        return ComComplex([i+j for i,j in zip(self.value,x.value)])
    def __mul__(self,x):
        a = self.value[0]*x.value[0]-self.value[1]*x.value[1]-self.value[2]*x.value[2]-self.value[3]*x.value[3]
        b = self.value[0]*x.value[1]+self.value[1]*x.value[0]+self.value[2]*x.value[3]-self.value[3]*x.value[2]
        c = self.value[0]*x.value[2]-self.value[1]*x.value[3]+self.value[2]*x.value[0]+self.value[3]*x.value[1]
        d = self.value[0]*x.value[3]+self.value[1]*x.value[2]-self.value[2]*x.value[1]+self.value[3]*x.value[0]
        return ComComplex([a,b,c,d])
    def __mod__(self,x):
        return ComComplex([i % x for i in self.value])
    def __pow__(self, x, n=None):
        tmp = ComComplex(self.value)
        a = ComComplex([1,0,0,0])
        while x:
            if x & 1:
                a *= tmp
            tmp *= tmp
            if n:
                a %= n
                tmp %= n
            x >>= 1
        return a

A = 375413371936
B = 452903063925
C = 418564633198
D = 452841062207

G0 = 
G1 = 
G2 = 
G3 = 

P = 

M = Matrix([
    [-B,      -C,      -D],
    [ A,      -D,       C],
    [ D,       A,      -B]
])
v = Matrix([G0 % P, G1 % P, G2 % P])

M_inv = M.inv_mod(P)
solution = M_inv * v
p1 = int(solution[0] % P)
q1 = int(solution[1] % P)
r1 = int(solution[2] % P)
print(p1,q1,r1)
```
然后本来想直接求flag，发现`e=65547`，不互素，拿个以前的crt直接用就行了
```python
from Crypto.Util.number import *
from Crypto.Util.number import GCD as gcd
class ComComplex:
    def __init__(self, value=[0,0,0,0]):
        self.value = value
    def __str__(self):
        s = str(self.value[0])
        for k,i in enumerate(self.value[1:]):
            if i >= 0:
                s += '+'
            s += str(i) +'ijk'[k]
        return s
    def __add__(self,x):
        return ComComplex([i+j for i,j in zip(self.value,x.value)])
    def __mul__(self,x):
        a = self.value[0]*x.value[0]-self.value[1]*x.value[1]-self.value[2]*x.value[2]-self.value[3]*x.value[3]
        b = self.value[0]*x.value[1]+self.value[1]*x.value[0]+self.value[2]*x.value[3]-self.value[3]*x.value[2]
        c = self.value[0]*x.value[2]-self.value[1]*x.value[3]+self.value[2]*x.value[0]+self.value[3]*x.value[1]
        d = self.value[0]*x.value[3]+self.value[1]*x.value[2]-self.value[2]*x.value[1]+self.value[3]*x.value[0]
        return ComComplex([a,b,c,d])
    def __mod__(self,x):
        return ComComplex([i % x for i in self.value])
    def __pow__(self, x, n=None):
        tmp = ComComplex(self.value)
        a = ComComplex([1,0,0,0])
        while x:
            if x & 1:
                a *= tmp
            tmp *= tmp
            if n:
                a %= n
                tmp %= n
            x >>= 1
        return a
p,q,r=
e=65547
c = ComComplex([])
pqr=[p,q,r]
def inver_d(s):
   phi_s = s *(s-1)*(s**2-1)
   g_s = gcd(e, phi_s)
   phi_prime = phi_s // g_s
   d = inverse(e, phi_prime)
   return d

dp=inver_d(p)
dq=inver_d(q)
dr=inver_d(r)

cp=c%p
cq=c%q
cr=c%r

mp=pow(cp,dp,p)
mq=pow(cq,dq,q)
mr=pow(cr,dr,r)
def crt(shares):
    """中国剩余定理合并多个四元复数的每一分量"""
    res = []
    for i in range(4):
        # 提取每个四元数第 i 位的值 和对应模数
        a = [s.value[i] for s, _ in shares]
        m = [mod for _, mod in shares]
        # 使用单分量CRT合并结果
        res.append(int(crt_r(a, m)))
    return ComComplex(res)

def crt_r(a, m):
    """中国剩余定理求解单个整数分量"""
    M = 1
    for mi in m:
        M *= mi  # 总模数 M 是所有模数的乘积
    
    res = 0
    for ai, mi in zip(a, m):
        Mi = M // mi 
        inv = inverse(Mi, mi) 
        res = (res + ai * Mi * inv) % M 
    
    return res


m=crt([(mp,p),(mq,q),(mr,r)])

mm = []
for ms in m.value:
    mm.append(long_to_bytes(ms))

flag = b''.join(mm)
print(flag.decode())
```

### choice
choice.py
```python
from Crypto.Util.number import bytes_to_long
from random import Random
from secret import flag

assert flag.startswith(b'XYCTF{') and flag.endswith(b'}')
flag = flag[6:-1]

msg = bytes_to_long(flag)
rand = Random()
test = bytes([i for i in range(255, -1, -1)])
open('output.py', 'w').write(f'enc = {msg ^ rand.getrandbits(msg.bit_length())}\nr = {[rand.choice(test) for _ in range(2496)]}')
```
random.py
```python
"""Random variable generators.

    bytes
    -----
           uniform bytes (values between 0 and 255)

    integers
    --------
           uniform within range

    sequences
    ---------
           pick random element
           pick random sample
           pick weighted random sample
           generate random permutation

    distributions on the real line:
    ------------------------------
           uniform
           triangular
           normal (Gaussian)
           lognormal
           negative exponential
           gamma
           beta
           pareto
           Weibull

    distributions on the circle (angles 0 to 2pi)
    ---------------------------------------------
           circular uniform
           von Mises

    discrete distributions
    ----------------------
           binomial


General notes on the underlying Mersenne Twister core generator:

* The period is 2**19937-1.
* It is one of the most extensively tested generators in existence.
* The random() method is implemented in C, executes in a single Python step,
  and is, therefore, threadsafe.

"""

# Translated by Guido van Rossum from C source provided by
# Adrian Baddeley.  Adapted by Raymond Hettinger for use with
# the Mersenne Twister  and os.urandom() core generators.

from warnings import warn as _warn
from math import log as _log, exp as _exp, pi as _pi, e as _e, ceil as _ceil
from math import sqrt as _sqrt, acos as _acos, cos as _cos, sin as _sin
from math import tau as TWOPI, floor as _floor, isfinite as _isfinite
from math import lgamma as _lgamma, fabs as _fabs, log2 as _log2
from os import urandom as _urandom
from _collections_abc import Sequence as _Sequence
from operator import index as _index
from itertools import accumulate as _accumulate, repeat as _repeat
from bisect import bisect as _bisect
import os as _os
import _random

try:
    # hashlib is pretty heavy to load, try lean internal module first
    from _sha2 import sha512 as _sha512
except ImportError:
    # fallback to official implementation
    from hashlib import sha512 as _sha512

__all__ = [
    "Random",
    "SystemRandom",
    "betavariate",
    "binomialvariate",
    "choice",
    "choices",
    "expovariate",
    "gammavariate",
    "gauss",
    "getrandbits",
    "getstate",
    "lognormvariate",
    "normalvariate",
    "paretovariate",
    "randbytes",
    "randint",
    "random",
    "randrange",
    "sample",
    "seed",
    "setstate",
    "shuffle",
    "triangular",
    "uniform",
    "vonmisesvariate",
    "weibullvariate",
]

NV_MAGICCONST = 4 * _exp(-0.5) / _sqrt(2.0)
LOG4 = _log(4.0)
SG_MAGICCONST = 1.0 + _log(4.5)
BPF = 53        # Number of bits in a float
RECIP_BPF = 2 ** -BPF
_ONE = 1


class Random(_random.Random):
    """Random number generator base class used by bound module functions.

    Used to instantiate instances of Random to get generators that don't
    share state.

    Class Random can also be subclassed if you want to use a different basic
    generator of your own devising: in that case, override the following
    methods:  random(), seed(), getstate(), and setstate().
    Optionally, implement a getrandbits() method so that randrange()
    can cover arbitrarily large ranges.

    """

    VERSION = 3     # used by getstate/setstate

    def __init__(self, x=None):
        """Initialize an instance.

        Optional argument x controls seeding, as for Random.seed().
        """

        self.seed(x)
        self.gauss_next = None

    def seed(self, a=None, version=2):
        """Initialize internal state from a seed.

        The only supported seed types are None, int, float,
        str, bytes, and bytearray.

        None or no argument seeds from current time or from an operating
        system specific randomness source if available.

        If *a* is an int, all bits are used.

        For version 2 (the default), all of the bits are used if *a* is a str,
        bytes, or bytearray.  For version 1 (provided for reproducing random
        sequences from older versions of Python), the algorithm for str and
        bytes generates a narrower range of seeds.

        """

        if version == 1 and isinstance(a, (str, bytes)):
            a = a.decode('latin-1') if isinstance(a, bytes) else a
            x = ord(a[0]) << 7 if a else 0
            for c in map(ord, a):
                x = ((1000003 * x) ^ c) & 0xFFFFFFFFFFFFFFFF
            x ^= len(a)
            a = -2 if x == -1 else x

        elif version == 2 and isinstance(a, (str, bytes, bytearray)):
            if isinstance(a, str):
                a = a.encode()
            a = int.from_bytes(a + _sha512(a).digest())

        elif not isinstance(a, (type(None), int, float, str, bytes, bytearray)):
            raise TypeError('The only supported seed types are: None,\n'
                            'int, float, str, bytes, and bytearray.')

        super().seed(a)
        self.gauss_next = None

    def getstate(self):
        """Return internal state; can be passed to setstate() later."""
        return self.VERSION, super().getstate(), self.gauss_next

    def setstate(self, state):
        """Restore internal state from object returned by getstate()."""
        version = state[0]
        if version == 3:
            version, internalstate, self.gauss_next = state
            super().setstate(internalstate)
        elif version == 2:
            version, internalstate, self.gauss_next = state
            # In version 2, the state was saved as signed ints, which causes
            #   inconsistencies between 32/64-bit systems. The state is
            #   really unsigned 32-bit ints, so we convert negative ints from
            #   version 2 to positive longs for version 3.
            try:
                internalstate = tuple(x % (2 ** 32) for x in internalstate)
            except ValueError as e:
                raise TypeError from e
            super().setstate(internalstate)
        else:
            raise ValueError("state with version %s passed to "
                             "Random.setstate() of version %s" %
                             (version, self.VERSION))


    ## -------------------------------------------------------
    ## ---- Methods below this point do not need to be overridden or extended
    ## ---- when subclassing for the purpose of using a different core generator.


    ## -------------------- pickle support  -------------------

    # Issue 17489: Since __reduce__ was defined to fix #759889 this is no
    # longer called; we leave it here because it has been here since random was
    # rewritten back in 2001 and why risk breaking something.
    def __getstate__(self):  # for pickle
        return self.getstate()

    def __setstate__(self, state):  # for pickle
        self.setstate(state)

    def __reduce__(self):
        return self.__class__, (), self.getstate()


    ## ---- internal support method for evenly distributed integers ----

    def __init_subclass__(cls, /, **kwargs):
        """Control how subclasses generate random integers.

        The algorithm a subclass can use depends on the random() and/or
        getrandbits() implementation available to it and determines
        whether it can generate random integers from arbitrarily large
        ranges.
        """

        for c in cls.__mro__:
            if '_randbelow' in c.__dict__:
                # just inherit it
                break
            if 'getrandbits' in c.__dict__:
                cls._randbelow = cls._randbelow_with_getrandbits
                break
            if 'random' in c.__dict__:
                cls._randbelow = cls._randbelow_without_getrandbits
                break

    def _randbelow_with_getrandbits(self, n):
        "Return a random int in the range [0,n).  Defined for n > 0."

        getrandbits = self.getrandbits
        k = n.bit_length() - 1
        r = getrandbits(k)  # 0 <= r < 2**k
        while r >= n:
            r = getrandbits(k)
        return r

    def _randbelow_without_getrandbits(self, n, maxsize=1<<BPF):
        """Return a random int in the range [0,n).  Defined for n > 0.

        The implementation does not use getrandbits, but only random.
        """

        random = self.random
        if n >= maxsize:
            _warn("Underlying random() generator does not supply \n"
                "enough bits to choose from a population range this large.\n"
                "To remove the range limitation, add a getrandbits() method.")
            return _floor(random() * n)
        rem = maxsize % n
        limit = (maxsize - rem) / maxsize   # int(limit * maxsize) % n == 0
        r = random()
        while r >= limit:
            r = random()
        return _floor(r * maxsize) % n

    _randbelow = _randbelow_with_getrandbits


    ## --------------------------------------------------------
    ## ---- Methods below this point generate custom distributions
    ## ---- based on the methods defined above.  They do not
    ## ---- directly touch the underlying generator and only
    ## ---- access randomness through the methods:  random(),
    ## ---- getrandbits(), or _randbelow().


    ## -------------------- bytes methods ---------------------

    def randbytes(self, n):
        """Generate n random bytes."""
        return self.getrandbits(n * 8).to_bytes(n, 'little')


    ## -------------------- integer methods  -------------------

    def randrange(self, start, stop=None, step=_ONE):
        """Choose a random item from range(stop) or range(start, stop[, step]).

        Roughly equivalent to ``choice(range(start, stop, step))`` but
        supports arbitrarily large ranges and is optimized for common cases.

        """

        # This code is a bit messy to make it fast for the
        # common case while still doing adequate error checking.
        istart = _index(start)
        if stop is None:
            # We don't check for "step != 1" because it hasn't been
            # type checked and converted to an integer yet.
            if step is not _ONE:
                raise TypeError("Missing a non-None stop argument")
            if istart > 0:
                return self._randbelow(istart)
            raise ValueError("empty range for randrange()")

        # Stop argument supplied.
        istop = _index(stop)
        width = istop - istart
        istep = _index(step)
        # Fast path.
        if istep == 1:
            if width > 0:
                return istart + self._randbelow(width)
            raise ValueError(f"empty range in randrange({start}, {stop})")

        # Non-unit step argument supplied.
        if istep > 0:
            n = (width + istep - 1) // istep
        elif istep < 0:
            n = (width + istep + 1) // istep
        else:
            raise ValueError("zero step for randrange()")
        if n <= 0:
            raise ValueError(f"empty range in randrange({start}, {stop}, {step})")
        return istart + istep * self._randbelow(n)

    def randint(self, a, b):
        """Return random integer in range [a, b], including both end points.
        """

        return self.randrange(a, b+1)


    ## -------------------- sequence methods  -------------------

    def choice(self, seq):
        """Choose a random element from a non-empty sequence."""

        # As an accommodation for NumPy, we don't use "if not seq"
        # because bool(numpy.array()) raises a ValueError.
        if not len(seq):
            raise IndexError('Cannot choose from an empty sequence')
        return seq[self._randbelow(len(seq))]

    def shuffle(self, x):
        """Shuffle list x in place, and return None."""

        randbelow = self._randbelow
        for i in reversed(range(1, len(x))):
            # pick an element in x[:i+1] with which to exchange x[i]
            j = randbelow(i + 1)
            x[i], x[j] = x[j], x[i]

    def sample(self, population, k, *, counts=None):
        """Chooses k unique random elements from a population sequence.

        Returns a new list containing elements from the population while
        leaving the original population unchanged.  The resulting list is
        in selection order so that all sub-slices will also be valid random
        samples.  This allows raffle winners (the sample) to be partitioned
        into grand prize and second place winners (the subslices).

        Members of the population need not be hashable or unique.  If the
        population contains repeats, then each occurrence is a possible
        selection in the sample.

        Repeated elements can be specified one at a time or with the optional
        counts parameter.  For example:

            sample(['red', 'blue'], counts=[4, 2], k=5)

        is equivalent to:

            sample(['red', 'red', 'red', 'red', 'blue', 'blue'], k=5)

        To choose a sample from a range of integers, use range() for the
        population argument.  This is especially fast and space efficient
        for sampling from a large population:

            sample(range(10000000), 60)

        """

        # Sampling without replacement entails tracking either potential
        # selections (the pool) in a list or previous selections in a set.

        # When the number of selections is small compared to the
        # population, then tracking selections is efficient, requiring
        # only a small set and an occasional reselection.  For
        # a larger number of selections, the pool tracking method is
        # preferred since the list takes less space than the
        # set and it doesn't suffer from frequent reselections.

        # The number of calls to _randbelow() is kept at or near k, the
        # theoretical minimum.  This is important because running time
        # is dominated by _randbelow() and because it extracts the
        # least entropy from the underlying random number generators.

        # Memory requirements are kept to the smaller of a k-length
        # set or an n-length list.

        # There are other sampling algorithms that do not require
        # auxiliary memory, but they were rejected because they made
        # too many calls to _randbelow(), making them slower and
        # causing them to eat more entropy than necessary.

        if not isinstance(population, _Sequence):
            raise TypeError("Population must be a sequence.  "
                            "For dicts or sets, use sorted(d).")
        n = len(population)
        if counts is not None:
            cum_counts = list(_accumulate(counts))
            if len(cum_counts) != n:
                raise ValueError('The number of counts does not match the population')
            total = cum_counts.pop()
            if not isinstance(total, int):
                raise TypeError('Counts must be integers')
            if total <= 0:
                raise ValueError('Total of counts must be greater than zero')
            selections = self.sample(range(total), k=k)
            bisect = _bisect
            return [population[bisect(cum_counts, s)] for s in selections]
        randbelow = self._randbelow
        if not 0 <= k <= n:
            raise ValueError("Sample larger than population or is negative")
        result = [None] * k
        setsize = 21        # size of a small set minus size of an empty list
        if k > 5:
            setsize += 4 ** _ceil(_log(k * 3, 4))  # table size for big sets
        if n <= setsize:
            # An n-length list is smaller than a k-length set.
            # Invariant:  non-selected at pool[0 : n-i]
            pool = list(population)
            for i in range(k):
                j = randbelow(n - i)
                result[i] = pool[j]
                pool[j] = pool[n - i - 1]  # move non-selected item into vacancy
        else:
            selected = set()
            selected_add = selected.add
            for i in range(k):
                j = randbelow(n)
                while j in selected:
                    j = randbelow(n)
                selected_add(j)
                result[i] = population[j]
        return result

    def choices(self, population, weights=None, *, cum_weights=None, k=1):
        """Return a k sized list of population elements chosen with replacement.

        If the relative weights or cumulative weights are not specified,
        the selections are made with equal probability.

        """
        random = self.random
        n = len(population)
        if cum_weights is None:
            if weights is None:
                floor = _floor
                n += 0.0    # convert to float for a small speed improvement
                return [population[floor(random() * n)] for i in _repeat(None, k)]
            try:
                cum_weights = list(_accumulate(weights))
            except TypeError:
                if not isinstance(weights, int):
                    raise
                k = weights
                raise TypeError(
                    f'The number of choices must be a keyword argument: {k=}'
                ) from None
        elif weights is not None:
            raise TypeError('Cannot specify both weights and cumulative weights')
        if len(cum_weights) != n:
            raise ValueError('The number of weights does not match the population')
        total = cum_weights[-1] + 0.0   # convert to float
        if total <= 0.0:
            raise ValueError('Total of weights must be greater than zero')
        if not _isfinite(total):
            raise ValueError('Total of weights must be finite')
        bisect = _bisect
        hi = n - 1
        return [population[bisect(cum_weights, random() * total, 0, hi)]
                for i in _repeat(None, k)]


    ## -------------------- real-valued distributions  -------------------

    def uniform(self, a, b):
        """Get a random number in the range [a, b) or [a, b] depending on rounding.

        The mean (expected value) and variance of the random variable are:

            E[X] = (a + b) / 2
            Var[X] = (b - a) ** 2 / 12

        """
        return a + (b - a) * self.random()

    def triangular(self, low=0.0, high=1.0, mode=None):
        """Triangular distribution.

        Continuous distribution bounded by given lower and upper limits,
        and having a given mode value in-between.

        http://en.wikipedia.org/wiki/Triangular_distribution

        The mean (expected value) and variance of the random variable are:

            E[X] = (low + high + mode) / 3
            Var[X] = (low**2 + high**2 + mode**2 - low*high - low*mode - high*mode) / 18

        """
        u = self.random()
        try:
            c = 0.5 if mode is None else (mode - low) / (high - low)
        except ZeroDivisionError:
            return low
        if u > c:
            u = 1.0 - u
            c = 1.0 - c
            low, high = high, low
        return low + (high - low) * _sqrt(u * c)

    def normalvariate(self, mu=0.0, sigma=1.0):
        """Normal distribution.

        mu is the mean, and sigma is the standard deviation.

        """
        # Uses Kinderman and Monahan method. Reference: Kinderman,
        # A.J. and Monahan, J.F., "Computer generation of random
        # variables using the ratio of uniform deviates", ACM Trans
        # Math Software, 3, (1977), pp257-260.

        random = self.random
        while True:
            u1 = random()
            u2 = 1.0 - random()
            z = NV_MAGICCONST * (u1 - 0.5) / u2
            zz = z * z / 4.0
            if zz <= -_log(u2):
                break
        return mu + z * sigma

    def gauss(self, mu=0.0, sigma=1.0):
        """Gaussian distribution.

        mu is the mean, and sigma is the standard deviation.  This is
        slightly faster than the normalvariate() function.

        Not thread-safe without a lock around calls.

        """
        # When x and y are two variables from [0, 1), uniformly
        # distributed, then
        #
        #    cos(2*pi*x)*sqrt(-2*log(1-y))
        #    sin(2*pi*x)*sqrt(-2*log(1-y))
        #
        # are two *independent* variables with normal distribution
        # (mu = 0, sigma = 1).
        # (Lambert Meertens)
        # (corrected version; bug discovered by Mike Miller, fixed by LM)

        # Multithreading note: When two threads call this function
        # simultaneously, it is possible that they will receive the
        # same return value.  The window is very small though.  To
        # avoid this, you have to use a lock around all calls.  (I
        # didn't want to slow this down in the serial case by using a
        # lock here.)

        random = self.random
        z = self.gauss_next
        self.gauss_next = None
        if z is None:
            x2pi = random() * TWOPI
            g2rad = _sqrt(-2.0 * _log(1.0 - random()))
            z = _cos(x2pi) * g2rad
            self.gauss_next = _sin(x2pi) * g2rad

        return mu + z * sigma

    def lognormvariate(self, mu, sigma):
        """Log normal distribution.

        If you take the natural logarithm of this distribution, you'll get a
        normal distribution with mean mu and standard deviation sigma.
        mu can have any value, and sigma must be greater than zero.

        """
        return _exp(self.normalvariate(mu, sigma))

    def expovariate(self, lambd=1.0):
        """Exponential distribution.

        lambd is 1.0 divided by the desired mean.  It should be
        nonzero.  (The parameter would be called "lambda", but that is
        a reserved word in Python.)  Returned values range from 0 to
        positive infinity if lambd is positive, and from negative
        infinity to 0 if lambd is negative.

        The mean (expected value) and variance of the random variable are:

            E[X] = 1 / lambd
            Var[X] = 1 / lambd ** 2

        """
        # we use 1-random() instead of random() to preclude the
        # possibility of taking the log of zero.

        return -_log(1.0 - self.random()) / lambd

    def vonmisesvariate(self, mu, kappa):
        """Circular data distribution.

        mu is the mean angle, expressed in radians between 0 and 2*pi, and
        kappa is the concentration parameter, which must be greater than or
        equal to zero.  If kappa is equal to zero, this distribution reduces
        to a uniform random angle over the range 0 to 2*pi.

        """
        # Based upon an algorithm published in: Fisher, N.I.,
        # "Statistical Analysis of Circular Data", Cambridge
        # University Press, 1993.

        # Thanks to Magnus Kessler for a correction to the
        # implementation of step 4.

        random = self.random
        if kappa <= 1e-6:
            return TWOPI * random()

        s = 0.5 / kappa
        r = s + _sqrt(1.0 + s * s)

        while True:
            u1 = random()
            z = _cos(_pi * u1)

            d = z / (r + z)
            u2 = random()
            if u2 < 1.0 - d * d or u2 <= (1.0 - d) * _exp(d):
                break

        q = 1.0 / r
        f = (q + z) / (1.0 + q * z)
        u3 = random()
        if u3 > 0.5:
            theta = (mu + _acos(f)) % TWOPI
        else:
            theta = (mu - _acos(f)) % TWOPI

        return theta

    def gammavariate(self, alpha, beta):
        """Gamma distribution.  Not the gamma function!

        Conditions on the parameters are alpha > 0 and beta > 0.

        The probability distribution function is:

                    x ** (alpha - 1) * math.exp(-x / beta)
          pdf(x) =  --------------------------------------
                      math.gamma(alpha) * beta ** alpha

        The mean (expected value) and variance of the random variable are:

            E[X] = alpha * beta
            Var[X] = alpha * beta ** 2

        """

        # Warning: a few older sources define the gamma distribution in terms
        # of alpha > -1.0
        if alpha <= 0.0 or beta <= 0.0:
            raise ValueError('gammavariate: alpha and beta must be > 0.0')

        random = self.random
        if alpha > 1.0:

            # Uses R.C.H. Cheng, "The generation of Gamma
            # variables with non-integral shape parameters",
            # Applied Statistics, (1977), 26, No. 1, p71-74

            ainv = _sqrt(2.0 * alpha - 1.0)
            bbb = alpha - LOG4
            ccc = alpha + ainv

            while True:
                u1 = random()
                if not 1e-7 < u1 < 0.9999999:
                    continue
                u2 = 1.0 - random()
                v = _log(u1 / (1.0 - u1)) / ainv
                x = alpha * _exp(v)
                z = u1 * u1 * u2
                r = bbb + ccc * v - x
                if r + SG_MAGICCONST - 4.5 * z >= 0.0 or r >= _log(z):
                    return x * beta

        elif alpha == 1.0:
            # expovariate(1/beta)
            return -_log(1.0 - random()) * beta

        else:
            # alpha is between 0 and 1 (exclusive)
            # Uses ALGORITHM GS of Statistical Computing - Kennedy & Gentle
            while True:
                u = random()
                b = (_e + alpha) / _e
                p = b * u
                if p <= 1.0:
                    x = p ** (1.0 / alpha)
                else:
                    x = -_log((b - p) / alpha)
                u1 = random()
                if p > 1.0:
                    if u1 <= x ** (alpha - 1.0):
                        break
                elif u1 <= _exp(-x):
                    break
            return x * beta

    def betavariate(self, alpha, beta):
        """Beta distribution.

        Conditions on the parameters are alpha > 0 and beta > 0.
        Returned values range between 0 and 1.

        The mean (expected value) and variance of the random variable are:

            E[X] = alpha / (alpha + beta)
            Var[X] = alpha * beta / ((alpha + beta)**2 * (alpha + beta + 1))

        """
        ## See
        ## http://mail.python.org/pipermail/python-bugs-list/2001-January/003752.html
        ## for Ivan Frohne's insightful analysis of why the original implementation:
        ##
        ##    def betavariate(self, alpha, beta):
        ##        # Discrete Event Simulation in C, pp 87-88.
        ##
        ##        y = self.expovariate(alpha)
        ##        z = self.expovariate(1.0/beta)
        ##        return z/(y+z)
        ##
        ## was dead wrong, and how it probably got that way.

        # This version due to Janne Sinkkonen, and matches all the std
        # texts (e.g., Knuth Vol 2 Ed 3 pg 134 "the beta distribution").
        y = self.gammavariate(alpha, 1.0)
        if y:
            return y / (y + self.gammavariate(beta, 1.0))
        return 0.0

    def paretovariate(self, alpha):
        """Pareto distribution.  alpha is the shape parameter."""
        # Jain, pg. 495

        u = 1.0 - self.random()
        return u ** (-1.0 / alpha)

    def weibullvariate(self, alpha, beta):
        """Weibull distribution.

        alpha is the scale parameter and beta is the shape parameter.

        """
        # Jain, pg. 499; bug fix courtesy Bill Arms

        u = 1.0 - self.random()
        return alpha * (-_log(u)) ** (1.0 / beta)


    ## -------------------- discrete  distributions  ---------------------

    def binomialvariate(self, n=1, p=0.5):
        """Binomial random variable.

        Gives the number of successes for *n* independent trials
        with the probability of success in each trial being *p*:

            sum(random() < p for i in range(n))

        Returns an integer in the range:   0 <= X <= n

        The mean (expected value) and variance of the random variable are:

            E[X] = n * p
            Var[x] = n * p * (1 - p)

        """
        # Error check inputs and handle edge cases
        if n < 0:
            raise ValueError("n must be non-negative")
        if p <= 0.0 or p >= 1.0:
            if p == 0.0:
                return 0
            if p == 1.0:
                return n
            raise ValueError("p must be in the range 0.0 <= p <= 1.0")

        random = self.random

        # Fast path for a common case
        if n == 1:
            return _index(random() < p)

        # Exploit symmetry to establish:  p <= 0.5
        if p > 0.5:
            return n - self.binomialvariate(n, 1.0 - p)

        if n * p < 10.0:
            # BG: Geometric method by Devroye with running time of O(np).
            # https://dl.acm.org/doi/pdf/10.1145/42372.42381
            x = y = 0
            c = _log2(1.0 - p)
            if not c:
                return x
            while True:
                y += _floor(_log2(random()) / c) + 1
                if y > n:
                    return x
                x += 1

        # BTRS: Transformed rejection with squeeze method by Wolfgang Hörmann
        # https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.47.8407&rep=rep1&type=pdf
        assert n*p >= 10.0 and p <= 0.5
        setup_complete = False

        spq = _sqrt(n * p * (1.0 - p))  # Standard deviation of the distribution
        b = 1.15 + 2.53 * spq
        a = -0.0873 + 0.0248 * b + 0.01 * p
        c = n * p + 0.5
        vr = 0.92 - 4.2 / b

        while True:

            u = random()
            u -= 0.5
            us = 0.5 - _fabs(u)
            k = _floor((2.0 * a / us + b) * u + c)
            if k < 0 or k > n:
                continue

            # The early-out "squeeze" test substantially reduces
            # the number of acceptance condition evaluations.
            v = random()
            if us >= 0.07 and v <= vr:
                return k

            # Acceptance-rejection test.
            # Note, the original paper erroneously omits the call to log(v)
            # when comparing to the log of the rescaled binomial distribution.
            if not setup_complete:
                alpha = (2.83 + 5.1 / b) * spq
                lpq = _log(p / (1.0 - p))
                m = _floor((n + 1) * p)         # Mode of the distribution
                h = _lgamma(m + 1) + _lgamma(n - m + 1)
                setup_complete = True           # Only needs to be done once
            v *= alpha / (a / (us * us) + b)
            if _log(v) <= h - _lgamma(k + 1) - _lgamma(n - k + 1) + (k - m) * lpq:
                return k


## ------------------------------------------------------------------
## --------------- Operating System Random Source  ------------------


class SystemRandom(Random):
    """Alternate random number generator using sources provided
    by the operating system (such as /dev/urandom on Unix or
    CryptGenRandom on Windows).

     Not available on all systems (see os.urandom() for details).

    """

    def random(self):
        """Get the next random number in the range 0.0 <= X < 1.0."""
        return (int.from_bytes(_urandom(7)) >> 3) * RECIP_BPF

    def getrandbits(self, k):
        """getrandbits(k) -> x.  Generates an int with k random bits."""
        if k < 0:
            raise ValueError('number of bits must be non-negative')
        numbytes = (k + 7) // 8                       # bits / 8 and rounded up
        x = int.from_bytes(_urandom(numbytes))
        return x >> (numbytes * 8 - k)                # trim excess bits

    def randbytes(self, n):
        """Generate n random bytes."""
        # os.urandom(n) fails with ValueError for n < 0
        # and returns an empty bytes string for n == 0.
        return _urandom(n)

    def seed(self, *args, **kwds):
        "Stub method.  Not used for a system random number generator."
        return None

    def _notimplemented(self, *args, **kwds):
        "Method should not be called for a system random number generator."
        raise NotImplementedError('System entropy source does not have state.')
    getstate = setstate = _notimplemented


# ----------------------------------------------------------------------
# Create one instance, seeded from current time, and export its methods
# as module-level functions.  The functions share state across all uses
# (both in the user's code and in the Python libraries), but that's fine
# for most programs and is easier for the casual user than making them
# instantiate their own Random() instance.

_inst = Random()
seed = _inst.seed
random = _inst.random
uniform = _inst.uniform
triangular = _inst.triangular
randint = _inst.randint
choice = _inst.choice
randrange = _inst.randrange
sample = _inst.sample
shuffle = _inst.shuffle
choices = _inst.choices
normalvariate = _inst.normalvariate
lognormvariate = _inst.lognormvariate
expovariate = _inst.expovariate
vonmisesvariate = _inst.vonmisesvariate
gammavariate = _inst.gammavariate
gauss = _inst.gauss
betavariate = _inst.betavariate
binomialvariate = _inst.binomialvariate
paretovariate = _inst.paretovariate
weibullvariate = _inst.weibullvariate
getstate = _inst.getstate
setstate = _inst.setstate
getrandbits = _inst.getrandbits
randbytes = _inst.randbytes


## ------------------------------------------------------
## ----------------- test program -----------------------

def _test_generator(n, func, args):
    from statistics import stdev, fmean as mean
    from time import perf_counter

    t0 = perf_counter()
    data = [func(*args) for i in _repeat(None, n)]
    t1 = perf_counter()

    xbar = mean(data)
    sigma = stdev(data, xbar)
    low = min(data)
    high = max(data)

    print(f'{t1 - t0:.3f} sec, {n} times {func.__name__}{args!r}')
    print('avg %g, stddev %g, min %g, max %g\n' % (xbar, sigma, low, high))


def _test(N=10_000):
    _test_generator(N, random, ())
    _test_generator(N, normalvariate, (0.0, 1.0))
    _test_generator(N, lognormvariate, (0.0, 1.0))
    _test_generator(N, vonmisesvariate, (0.0, 1.0))
    _test_generator(N, binomialvariate, (15, 0.60))
    _test_generator(N, binomialvariate, (100, 0.75))
    _test_generator(N, gammavariate, (0.01, 1.0))
    _test_generator(N, gammavariate, (0.1, 1.0))
    _test_generator(N, gammavariate, (0.1, 2.0))
    _test_generator(N, gammavariate, (0.5, 1.0))
    _test_generator(N, gammavariate, (0.9, 1.0))
    _test_generator(N, gammavariate, (1.0, 1.0))
    _test_generator(N, gammavariate, (2.0, 1.0))
    _test_generator(N, gammavariate, (20.0, 1.0))
    _test_generator(N, gammavariate, (200.0, 1.0))
    _test_generator(N, gauss, (0.0, 1.0))
    _test_generator(N, betavariate, (3.0, 3.0))
    _test_generator(N, triangular, (0.0, 1.0, 1.0 / 3.0))


## ------------------------------------------------------
## ------------------ fork support  ---------------------

if hasattr(_os, "fork"):
    _os.register_at_fork(after_in_child=_inst.seed)


if __name__ == '__main__':
    _test()
```

可以看到出题人自己搓了一个随机数脚本，其实就是`getrandbits(8)`?这个是真的不太懂，黄博士哪里有现成的脚本，直接梭哈出来78个256位的，也就和624个32位的等价了，然后`extend_mt19937_predictor`去恢复前一个随机数，但是会发现和enc的位数不太对，爆破一下就好了

exp.py
```python
from Crypto.Util.number import *
from random import *
from tqdm import *
from sage.all import *
r= []
rr = [255- x for x in r]

n=2496
D=rr[:n]
rng=Random()
def getRows(rng):
    #这一部分根据题目实际编写，必须和题目实际比特获取顺序和方式完全一致，且确保比特数大于19937，并且请注意zfill。
    row=[]
    for i in range(n):
        row+=list(map(int, (bin(rng.getrandbits(8))[2:].zfill(8))))
    return row
M=[]
for i in range(19968):#这一部分为固定套路，具体原因已经写在注释中了
    state = [0]*624
    temp = "0"*i + "1"*1 + "0"*(19968-1-i)
    for j in range(624):
        state[j] = int(temp[32*j:32*j+32],2)
    rng.setstate((3,tuple(state+[624]),None)) #这个setstate也是固定格式，已于2025.1.21测试
    M.append(getRows(rng))
M=Matrix(GF(2),M)
y=[]
for i in range(n):
    y+=list(map(int, (bin(D[i])[2:].zfill(8))))
y=vector(GF(2),y)
s=M.solve_left(y)
#print(s)
G=[]
for i in range(624):
    C=0
    for j in range(32):
        C<<=1
        C|=int(s[32*i+j])
    G.append(C)
import random
RNG1 = random.Random()
for i in range(624):
    G[i]=int(G[i])
RNG1.setstate((int(3),tuple(G+[int(624)]),None))

print([RNG1.getrandbits(256)for _ in range(78)])

import random
from extend_mt19937_predictor import ExtendMT19937Predictor
from Crypto.Util.number import long_to_bytes
rrr=[]
enc = 5042764371819053176884777909105310461303359296255297
n = enc.bit_length()

predictor = ExtendMT19937Predictor()

for i in range(78):
    predictor.setrandbits(rrr[i], 256)

_ = [predictor.backtrack_getrandbits(256) for _ in range(78)]

#爆破到3出来了
xx = predictor.backtrack_getrandbits(n + 3)

mm = enc ^ xx
print(long_to_bytes(mm))
```

### prng_xxxx
等官方wp吧

## 总结
质量真的挺高的，不愧是大恶人出的题(，但是队友的发挥，害，算了，吐槽到不想吐槽了