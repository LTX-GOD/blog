---
title: Tamuctf2025
published: 2025-03-31
pinned: false
description: Tamuctf2025 crypto wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-31
pubDate: 2025-03-31
---


## 前言
这是一个国外学校的比赛，密码质量很高

## 题目

### ECC
Can you get the secret key from the following two signed messages?

1st Message: "The secp256r1 curve was used."

2nd Message: "k value may have been re-used."

1st Signature r value: 91684750294663587590699225454580710947373104789074350179443937301009206290695

1st Signature s value: 8734396013686485452502025686012376394264288962663555711176194873788392352477

2nd Signature r value: 91684750294663587590699225454580710947373104789074350179443937301009206290695

2nd Signature s value: 96254287552668750588265978919231985627964457792323178870952715849103024292631

The flag is the secret key used to sign the messages. It will be in the flag format.
task
```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha256
from secret import sign

message1 = "The secp256r1 curve was used."
message2 = "k value may have been re-used."

message1 = bytes_to_long(sha256(message1.encode()).digest())
message2 = bytes_to_long(sha256(message2.encode()).digest())

r1, s1 = sign(message1)
r2, s2 = sign(message2)

print(f"r1: {r1}, s1: {s1}")
print(f"r2: {r2}, s2: {s2}")
```
很简单的ECDSA，直接计算即可
exp
```python
from hashlib import sha256
from Crypto.Util.number import*

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

message1 = "The secp256r1 curve was used."
message2 = "k value may have been re-used."

r = 91684750294663587590699225454580710947373104789074350179443937301009206290695
s1 = 8734396013686485452502025686012376394264288962663555711176194873788392352477
s2 = 96254287552668750588265978919231985627964457792323178870952715849103024292631

H_m1 = bytes_to_long(sha256(message1.encode()).digest())
H_m2 = bytes_to_long(sha256(message2.encode()).digest())
print(f"H(m1) = {H_m1}")
print(f"H(m2) = {H_m2}")

diff_h = (H_m1 - H_m2) % n
diff_s = (s1 - s2) % n
inv_diff_s = inverse(diff_s, n)
k = (diff_h * inv_diff_s) % n
print(f"k = {k}")
r_inv = inverse(r, n)
d = ((s1 * k - H_m1) % n) * r_inv % n
print(f"Private key d = {d}")

k_inv = inverse(k, n)
computed_s1 = (k_inv * (H_m1 + d * r)) % n
computed_s2 = (k_inv * (H_m2 + d * r)) % n

print(long_to_bytes(d))
```

### Mod
task
```python
import re
with open("flag.txt") as f:
    flag = f.read()
assert re.fullmatch(r"gigem\{[a-z0-9_]{38}\}",flag)
flag_num = int.from_bytes(flag.encode(), 'big')
assert flag_num % 114093090821120352479644063983906458923779848139997892783140659734927967458173 == 58809011802516045741268578327158509054400633329629779038362406616616290661238
```

一个很像小鸡块在nss的dlc出的题，但是更加复杂，鸡块的题大部分是在同一个范围，比如0~7，Nss这种有规律性的，或者是可以用线性表达的，但是这个题不行，我尝试了只用0~9的数字去求解flag，可以规约出来一组，但是并不是目标答案
官方预期解法
```python
import string  
import re
from sage.all import *

chrs = (string.ascii_letters + string.digits + "_").encode()  
avg = sorted(chrs)[len(chrs) // 2] - 1  
print(f"{avg = }")  
print([x - avg for x in sorted(chrs)])  # within [-37, 37]  
  
flaglen = 38
M = 114093090821120352479644063983906458923779848139997892783140659734927967458173
C = int.from_bytes(b"gigem{" + b"\x00" * flaglen + b"}", "big")  
rem = 58809011802516045741268578327158509054400633329629779038362406616616290661238
C -= rem

P = PolynomialRing(ZZ, "ap", flaglen)  
aps = P.gens()  
aa = [ap + avg for ap in aps]  
f = C + sum([a * 256**i for i, a in enumerate(aa)]) * 256  
print(f)  
  
L = matrix(f.coefficients()).T  
L = block_matrix([[M, 0], [L, 1]])  
bounds = [1] + [37] * flaglen + [1]  
scale = [2**20 // i for i in bounds]  
Q = diagonal_matrix(scale)  
L *= Q  
L = L.BKZ(block_size=25)  
L /= Q  

  
# not good enough  
# for row in L:  
#     if row[-1] < 0:  
#         row = -row  
#     if row[0] == 0 and row[-1] == 1:  
#         print(row)  
#         print(f(*row[1:-1]) % M == 0)  
#         aa = [x + avg for x in row[1:-1]][::-1]  
#         flag = b"gigem{" + bytes(aa) + b"}"  
#         
#         assert int.from_bytes(flag, "big") % M == rem  
#         print(flag)  
# exit()  

from fpylll import IntegerMatrix, LLL  
from fpylll.fplll.gso import MatGSO  
from fpylll.fplll.enumeration import Enumeration  
  
sols = []  
  
L[:, 0] *= 2**10  
A = IntegerMatrix.from_matrix(L.change_ring(ZZ))  
LLL.reduction(A)  
MG = MatGSO(A)  
MG.update_gso()  
sol_cnt = 10000  
enum = Enumeration(MG, sol_cnt)  
size = int(L.nrows())  
bound = 37  
answers = enum.enumerate(0, size, (size * bound**2), 0, pruning=None)  
for _, s in answers:  
    v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))  
    sv = v * A  
  
    if abs(sv[0, size - 1]) <= bound and sv[0, -1] in (-1, 1):  
        print(sv)  
        neg = sv[0, -1]  
        sol = [neg * sv[0, i + 1] for i in range(flaglen)]  
        assert f(*sol) % M == 0  
        aa = [x + avg for x in sol][::-1]  
        try:
            flag = b"gigem{" + bytes(aa) + b"}"  
        except:
            continue
        assert int.from_bytes(flag, "big") % M == rem
        print(flag)  
        
        try:  
            if re.fullmatch(r"gigem{\w{38}}", flag.decode()):  
                print("FOUND")  
                break  
        except UnicodeDecodeError:  
            pass  
```

赛后我用另一个赛题的wp中的方法运行三十分钟出来了，
链接https://connor-mccartney.github.io/cryptography/other/onelinecrypto-SeeTF-2023
```python
from Crypto.Util.number import *
from sage.all import *
import re

def lattice_enumeration(L, bound, sol_cnt=1_000_000):
    from fpylll import IntegerMatrix, LLL
    from fpylll.fplll.gso import MatGSO
    from fpylll.fplll.enumeration import Enumeration
    A = IntegerMatrix.from_matrix(L)
    LLL.reduction(A)
    M_mat = MatGSO(A)
    M_mat.update_gso()
    size = int(L.nrows())
    enum = Enumeration(M_mat, sol_cnt)
    answers = enum.enumerate(0, size, (size * bound**2), 0, pruning=None)
    print(f'Got {len(answers)} answers')
    for _, s in answers:
        # print(len(answers))
        v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))
        sv = v * A
        if abs(sv[0, size - 1]) <= bound:
            yield sv[0]

M_val = 114093090821120352479644063983906458923779848139997892783140659734927967458173
R_val = 58809011802516045741268578327158509054400633329629779038362406616616290661238

C = bytes_to_long(b"gigem{" + bytes(38) + b"}")
a = 85

dim = 38

M_lattice = (identity_matrix(dim)
    .augment(vector([0]*dim))
    .augment(vector([256**i for i in range(dim, 0, -1)]))
    .stack(vector([-a]*dim + [1, C - R_val]))
    .stack(vector([0]*dim + [0, -M_val]))
)

found = False
for row in lattice_enumeration(M_lattice.change_ring(ZZ), 37, sol_cnt=500_000):
    for sign in [1, -1]:
        r = [sign * x for x in row]
        if r[-2:] != [1, 0]:
            continue
        try:
            
            candidate = b"gigem{" + bytes([x + a for x in r[:-2]]) + b"}"
            if re.fullmatch(r"[a-z0-9_]{38}", candidate.decode()[6:-1]):
                if int.from_bytes(candidate, 'big') % M_val == R_val:
                    found = True
                    print(candidate)
                    break
        except Exception:
            continue
    
    if found:
        break
```

### Smelter
原附件有点大，不放了，个人感觉没mod恶心


exp
```python
SHA256_OID = (2, 16, 840, 1, 101, 3, 4, 2, 1)

class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.NamedType('parameters', univ.Null())
    )

class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('digest', univ.OctetString())
    )

def get_digestinfo(hash_bytes):
    alg = AlgorithmIdentifier()
    alg['algorithm'] = SHA256_OID
    alg['parameters'] = univ.Null()
    di = DigestInfo()
    di['digestAlgorithm'] = alg
    di['digest'] = hash_bytes
    return encoder.encode(di)

def integer_cube_root(n: int) -> int:
    low = 0
    high = 1 << ((n.bit_length() + 2) // 3)  
    while low < high:
        mid = (low + high) // 2
        if mid**3 < n:
            low = mid + 1
        else:
            high = mid
    if low**3 > n:
        low -= 1
    return low
# The Forgery Routin
def forge_signature():
    message = b"admin"
    h = hashlib.sha256(message).digest()
    t = get_digestinfo(h)
    minimal_prefix = b"\x00\x01\xff\x00" + t
    target_block = minimal_prefix.ljust(256, b"\x00")
    target_int = int.from_bytes(target_block, byteorder="big")
    s = integer_cube_root(target_int)
    while True:
        candidate = s**3
        candidate_bytes = candidate.to_bytes(256, byteorder="big")
        try:
            data_section = candidate_bytes[3:]
            sep_index = data_section.index(b"\x00")
            recovered = data_section[sep_index+1:]
        except Exception:
            recovered = b""
        if candidate_bytes.startswith(b"\x00\x01\xff\x00") and recovered.startswith(t):
            break
        s += 1

    forged_sig = s.to_bytes(256, byteorder="big")
    print("forged sing (b64):")
    print(base64.b64encode(forged_sig).decode())
    return forged_sig

if __name__ == "__main__":
    forge_signature()
```

### RC4
task
```python
from Crypto.Cipher import ARC4
import os
from string import printable
from random import choices

IV = ''.join(choices(printable,k=32)).encode()
for i in range(96):
    nonce = input("Give me a prefix (hex): ")
    try:
        nonce = bytes.fromhex(nonce)
    except:
        print("Make sure to send in hex.")
        exit()
    if len(nonce) + len(IV) > 256:
        print("Your prefix is too long.")
        exit()
    try:
        cipher = ARC4.new(nonce + IV)
    except:
        print("Could not create the cipher.")
        exit()
    
    pt = b"\0"
    ct = cipher.encrypt(pt)
    print(f"Your lucky number is {ord(ct)}")

guess = input("What was the IV(hex): ")
try:
    guess = bytes.fromhex(guess)
except:
    print("Make sure to send your guess for the IV in hex.")
    exit()
if IV == guess:
    with open("flag.txt","r") as f:
        FLAG = f.read()
        print(FLAG)
else:
    print(f"WRONG! IV was {IV.hex()}")

```
```python
from pwn import *

context.log_level = "debug"
io = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_rc4-prefix")
io.interactive(prompt="")

```
有一说一，不是特别熟，这里借鉴别的佬的代码，回头学会了单独写吧
exp
```python
from Crypto.Cipher import ARC4
import random
from pwn import *
from collections import Counter


def key_schedule(key):
    S = list(range(256))
    j = 0
    for i in range(len(key)):
        j = (j + S[i] + key[i]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def get_prefix(ind, known):
    while True:
        prefix = random.randbytes(256-32)
        key = prefix + known
        S = key_schedule(key)
        if (S[1] + S[S[1]])%256 == ind:
            return prefix

def oracle(prefix):
    io.sendline(prefix.hex())
    io.recvuntil(b'number is ')
    return int(io.recvline(keepends=False))
    
def Most_Common(lst):
    data = Counter(lst)
    return data.most_common(1)[0][0]

key = b'a'*32
known_key = b''
#context.log_level = "debug"

io = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_rc4-prefix")
#io = process("python3 ./RC4_prefix.py", shell=True)


for i in range(32):
    results = []
    for _ in range(3):
        prefix = get_prefix(256-32 + i, known_key)
        leak = oracle(prefix)
        for j in range(256):
            S = key_schedule(prefix + known_key + bytes([j]))
            if S[(S[1] + S[S[1]])%256] == leak:
                results.append(j)
    known_key += bytes([Most_Common(results)])
    print(known_key)

print(known_key.hex())
io.sendline(known_key.hex())
io.interactive()
```

## 总结
自己好菜啊啊啊啊啊啊啊啊啊啊