---
title: Litctf2025 Crypto
published: 2025-05-26
pinned: false
description: Litctf2025 Crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-05-26
pubDate: 2025-05-26
---


## 前言
赛时因为有其他的东西就没打，赛后复现，25号一晚上写完了，感觉除了背包其他的都还好

## 题目
### basic
task.py
```python
from Crypto.Util.number import *
from enc import flag 

m = bytes_to_long(flag)
n = getPrime(1024)
e = 65537
c = pow(m,e,n)
print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
```


经典的n是大素数的问题

exp.py
```python
n = 
e = 65537
c = 

from Crypto.Util.number import*
print(long_to_bytes(pow(c,inverse(e,n-1),n)))
```

### ez_math
task.py
```python
from sage.all import *
from Crypto.Util.number import *
from uuid import uuid4

flag = b'LitCTF{'+ str(uuid4()).encode() + b'}'
flag = bytes_to_long(flag)
len_flag = flag.bit_length()
e = 65537
p = getPrime(512)
P = GF(p)
A = [[flag,                 getPrime(len_flag)],
     [getPrime(len_flag),   getPrime(len_flag)]]
A = matrix(P, A)
B = A ** e

print(f"e = {e}")
print(f"p = {p}")
print(f"B = {list(B)}".replace('(', '[').replace(')', ']'))
```

就一个逆元xd

exp.py
```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
e = 65537
p = 
B =
P = GF(p)
B = matrix(P, B)

phi = p - 1
e_inv = inverse_mod(e, phi)

A = B ** e_inv

flag_int = A[0,0]

flag = long_to_bytes(int(flag_int))
print(flag.decode())
```

### baby
task.py
```python
import gmpy2
from Crypto.Util.number import *
from enc import flag


m = bytes_to_long(flag)
g = getPrime(512)
t = getPrime(150)
data = (t * gmpy2.invert(m, g)) % g
print(f'g = {g}')
print(f'data = {data}')
```

一个很经典的NTRU问题
$$
data=t*m^{-1} \mod g \\
data*m=t \mod g \\
t=data*m+kg 
$$

那么下面就可以造格了
$$
\begin{pmatrix}
m & k
\end{pmatrix} 
\begin{pmatrix}
1 & c \\
0 & g
\end{pmatrix}=\begin{pmatrix}
m & t
\end{pmatrix} 
$$

但是注意配平，我是直接尝试了一下
exp.py
```python
import libnum
from Crypto.Util.number import*
g = 
h = 

Ge = Matrix(ZZ,[[1,2**200*h],[0,2**200*g]])
m,t = Ge.LLL()[0]
m,t = abs(m),abs(t)

print(long_to_bytes(m))
```

### mmath
task.py
```python
from Crypto.Util.number import *
from enc import flag

m = bytes_to_long(flag)
e = 65537
p,q = getPrime(1024),getPrime(1024)
n = p*q
noise = getPrime(40)
tmp1 = noise*p+noise*q
tmp2 = noise*noise
hint = p*q+tmp1+tmp2
c = pow(m,e,n)
print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"hint = {hint}")
```

没给noise的值，很明显需要自己去化简
$$
res=hint-n=noise^2+noise(p+q)
$$

那么易知`noise`肯定是`res`的因子，factor一下就可以求出来了

exp.py
```python
n = 
e = 65537
c = 
hint = 
from Crypto.Util.number import *
res=hint-n
noise=942430120937#factor分解得到的
pq=(res-noise**2)//noise
print(pq)

from sympy import *
p, q = symbols('p q')

eq1 = p + q - pq
eq2 = p * q - n
solutions = solve((eq1, eq2), (p, q))
print("p 和 q 的解：", solutions)
p=
q=n//p
phi=(p-1)*(q-1)
print(long_to_bytes(pow(c,inverse(e,phi),n)))
```

### leak
exp.py
```python
from Crypto.Util.number import *
from enc import flag

m = bytes_to_long(flag)
p,q,e = getPrime(1024),getPrime(1024),getPrime(101)
n = p*q
temp = gmpy2.invert(e,p-1)
c = pow(m,e,n)
hint = temp>>180
print(f"e = {e}")
print(f"n = {n}")
print(f"c = {c}")
print(f"hint = {hint}")
```

第一开始被唬住了，后面发现和dp高位没区别的，直接打就行了

exp.py
```python
from Crypto.Util.number import *
import gmpy2
import itertools

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
        print(d)
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

e = 
n = 
c = 
leak = 
leak <<= 180
R.<x,y> = PolynomialRing(Zmod(n),implementation='generic')
f = e * (leak + x) + (y - 1)
res = small_roots(f,(2^180,2^101),m=2,d=4)
print(res)
for root in res:
    dp_low = root[0]
    dp = leak + dp_low
    tmp = pow(2,e*dp,n) - 2
    p = gmpy2.gcd(tmp,n)
    q = n // p
    d = inverse(e,(p-1)*(q-1))
    m = pow(c,d,n)
    print(long_to_bytes(m))
```

### new_bag
task.py
```python
from Crypto.Util.number import *
import random
import string
 
def get_flag(length):
    characters = string.ascii_letters + string.digits + '_'
    flag = 'LitCTF{' + ''.join(random.choice(characters) for _ in range(length)) + '}'
    return flag.encode()

flag = get_flag(8)
print(flag)
flag = bin(bytes_to_long(flag))[2:]

p = getPrime(128)
pubkey = [getPrime(128) for i in range(len(flag))]
enc = 0
for i in range(len(flag)):
    enc += pubkey[i] * int(flag[i])
    enc %= p
f = open("output.txt","w")
f.write(f"p = {p}\n")
f.write(f"pubkey = {pubkey}\n")
f.write(f"enc = {enc}\n")
f.close()
```

很经典的背包问题，有点像天融信安2023的一个题，但是中间填充方法不一样  
这个时候就有两种处理方法了，一个是先处理，一个是后处理  
后处理就是把字符列出来，然后直接寻找对应，比较暴力
exp.py
```python
from Crypto.Util.number import long_to_bytes
import re

def validate_flag(s):
    if not s.startswith(b'LitCTF{') or not s.endswith(b'}'):
        return False
    allowed_chars = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_')
    return all(c in allowed_chars for c in s[7:-1])

def attack(p, pubkey, enc, prefix=b'LitCTF{', suffix=b'}'):
    try:
        prefix_bits = bin(bytes_to_long(prefix))[2:]
        for i in range(len(prefix_bits)):
            enc = (enc - pubkey[i] * int(prefix_bits[i])) % p

        suffix_bits = bin(bytes_to_long(suffix))[2:].zfill(8)
        for i in range(-8, 0):
            enc = (enc - int(suffix_bits[i+8]) * pubkey[i]) % p

        mid_pubkey = pubkey[len(prefix_bits):-8]
        n = len(mid_pubkey)

        Ge = Matrix(ZZ, n + 2, n + 2)
        for i in range(n):
            Ge[i, i] = 1
            Ge[i, -1] = mid_pubkey[i]
        Ge[-2, -2] = 1
        Ge[-2, -1] = enc
        Ge[-1, -1] = p

        for vec in Ge.BKZ(block_size=25): 
            if vec[-1] != 0:
                continue
            bits = []
            valid = True
            for x in vec[:-2]:
                if abs(x) not in (0, 1):
                    valid = False
                    break
                bits.append('1' if x == 1 else '0')
            if not valid:
                continue
            
            mid_bits = ''.join(bits)
            full_bits = prefix_bits + mid_bits + suffix_bits
            try:
                flag = long_to_bytes(int(full_bits, 2))
                if validate_flag(flag):
                    return flag
            except:
                continue
        
        return b"Attack failed: No valid solution found"
    except Exception as e:
        return f"Error: {str(e)}".encode()

p = 
pubkey =
enc = 

flag = attack(p, pubkey, enc)
print(flag.decode())
```
这边直接用别人的脚本了，懒得改了，虽然还可以优化  

先处理的话就是先利用`b'LitCTF{' + b'\x00'*8 + b'}'`把他预处理一下，这个方法是学习dexter师傅的，很nb
```python
from Crypto.Util.number import *
from tqdm import *

p = 
pubkey =
enc = 

known = b'LitCTF{' + b'\x00'*8 + b'}'
bin_known = bin(bytes_to_long(known))[2:]
for i in range(len(bin_known)):
    enc -= pubkey[i] * int(bin_known[i])
    enc %= p

new_pubkey = pubkey[-72:-8]
n = len(new_pubkey)
d = n / log(max(new_pubkey), 2)
print(CDF(d))

for k in trange(256):
    S = enc + k*p
    L = Matrix(ZZ,n+1,n+1)
    for i in range(n):
        L[i,i] = 2
        L[-1,i] = 1
        L[i,-1] = new_pubkey[i]
    L[-1,-1] = S
    L[:,-1] *= 2^200

    for line in L.LLL():
        if set(line[:-1]).issubset({-1,1}):
            m = ''
            for i in line[:-1]:
                if i == 1:
                    m += '0'
                else:
                    m += '1'
            flag = b'LitCTF{' + long_to_bytes(int(m,2)) + b'}'
            print(flag)
```

## 总结
题比去年少了好多，但是质量挺高的，出了最后的背包都很新生