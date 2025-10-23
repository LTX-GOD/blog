---
title: 格学习笔记
published: 2025-06-29
pinned: false
description: 格密码学习笔记
tags: ['crypto','笔记']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-29
pubDate: 2025-06-29
---


## 前言

用来记录我的格密码学习，参考资料是NSS工坊和一些blog

## NTRU

### 1.入门题

task.py

```python
import gmpy2
from secret import flag
from Crypto.Util.number import *

f = bytes_to_long(flag)
p = getPrime(512)
g = getPrime(128)
h = gmpy2.invert(f+20192020202120222023, p) * g % p

print('h =', h)
print('p =', p)
```

想要flag就要求出f，f=f+20192020202120222023，最后减去这个数就好了，那么已知的式子就变成了

$$
h \equiv f^{-1}g \mod p \\
hf \equiv g \mod p \\
g=hf-kp \\
\begin{pmatrix}
f&-k
\end{pmatrix}
\begin{pmatrix}
1&h\\
0&p
\end{pmatrix}=
\begin{pmatrix}
f&g
\end{pmatrix}
$$

在本质的计算中，他是拿向量(h,1)(p,0)去做线性组合，如果两组是$x_1$$x_2$，那么就变成了
$x_1h+x_2p,x_1$，而当$x_1=f,x_2=-k$就是我们想要的结果  

exp.sage
```python
from sage.all import*
from Crypto.Util.number import *

h = 
p = 

zsm=Matrix(ZZ,[[1,h],[0,p]])
f,g=zsm.LLL()[0]
print(long_to_bytes(abs(f)-20192020202120222023))
```

与此题相似的还有LitCTF2025的baby，不过那个需要配平一下

### 2.HNCTF 2022 WEEK2

task.py
```python
from Crypto.Util.number import *
from hashlib import *

p = getPrime(2048)
f = getPrime(1024)
g = getPrime(768)
h = pow(f,-1,p)*g%p
verify = sha256(bytes.fromhex(hex(f+g)[2:])).hexdigest()
print(f'verify = {verify}')
print(f'p = {p}')
print(f'h = {h}')
print('NSSCTF{' + md5(bytes.fromhex(hex(f+g)[2:])).hexdigest() + '}')
```

$$
h\equiv f^{-1}g \mod p \\
hf\equiv g \mod p \\
g=hf-kp \\
\begin{pmatrix}
f&-k
\end{pmatrix}
\begin{pmatrix}
1&h\\
0&p
\end{pmatrix}=
\begin{pmatrix}
f&g
\end{pmatrix}
$$

你会发现和上一题差不多的感觉()

exp.sage
```python
from sage.all import*
from Crypto.Util.number import *
from hashlib import *
verify = ""
p = 
h = 


zsm=Matrix(ZZ,[[1,h],[0,p]])
f,g=zsm.LLL()[0]
if sha256(bytes.fromhex(hex(abs(f)+abs(g))[2:])).hexdigest() == verify:
    flag = 'NSSCTF{' + md5(bytes.fromhex(hex(f+g)[2:])).hexdigest() + '}'
    print(flag)
```

### 3.不知道哪来的

task.py

```python
from Crypto.Util.number import *
 
p = getPrime(1024)
 
f = getPrime(400)
g = getPrime(512)
r = getPrime(400)
 
h = inverse(f, p) * g % p
 
m = b'******'
m = bytes_to_long(m)
 
c = (r*h + m) % p
 
print(f'p = {p}')
print(f'h = {h}')
print(f'c = {c}')
```

先把h代入进去，然后化简

$$
c \equiv (r \times f^{-1} \times g+m) \mod p \\
fc \equiv (rg+mf) \mod p\\
mf \equiv (fc-rg) \mod p \\
mf \equiv fc \mod p \mod g \\
m \equiv (fc \mod p) \times f^{-1} \mod g
$$

要求m就要知道fcpg，cp已知，求fg

$$
\begin{pmatrix}
f&-k
\end{pmatrix}
\begin{pmatrix}
1&h\\
0&p
\end{pmatrix}=
\begin{pmatrix}
f&g
\end{pmatrix}
$$

exp.sage
```python
from sage.all import*
from Crypto.Util.number import *

p = 
h = 
c = 

zsm=Matrix(ZZ,[[1,h],[0,p]])
f,g=zsm.LLL()[0]
f,g=abs(f),abs(g)
m=((f*c%p)*inverse(f,g))%g
print(long_to_bytes(m))
```

### 4.深育杯2021

task.py

```python
from Crypto.Util.number import *
import gmpy2
from flag import flag

def encrypt(plaintext):
    p = getStrongPrime(3072) 
    m = bytes_to_long(plaintext)
    r = getRandomNBitInteger(1024)
    while True:
        f = getRandomNBitInteger(1024)
        g = getStrongPrime(768)
        h = gmpy2.invert(f, p) * g % p
        c = (r * h + m * f) % p
        return (h, p, c)

h, p, c = encrypt(flag)
with open("cipher.txt", "w") as f:
    f.write("h = " + str(h) + "\n")
    f.write("p = " + str(p) + "\n")
    f.write("c = " + str(c) + "\n")
```

格和前面构造的一样，主要是c的化简不一样，这里就省略了

## NSS工坊题目

### P3

task.py

```python
from Crypto.Util.number import *
import random

flag = b'******'
m = bytes_to_long(flag)

a = getPrime(1024)
b = getPrime(1536)

p = getPrime(512)
q = getPrime(512)
r = random.randint(2**14, 2**15)
assert ((p-r) * a + q) % b < 50

c = pow(m, 65537, p*q)

print(f'c = {c}')
print(f'a = {a}')
print(f'b = {b}')
```

$$
x \equiv ((p-r) \times a+q) \mod b \\
x-q \equiv (p-r)\times a \mod b \\
x-q=(p-r)\times a+kb \\
\begin{pmatrix}
p-r&k
\end{pmatrix}
\begin{pmatrix}
a&1\\
b&0
\end{pmatrix}=
\begin{pmatrix}
x-q&p-r
\end{pmatrix}
$$

xr都是很小的数，可以爆破，值得注意的是，先爆破r再爆破x会快一点xd

exp.sage

```python
from sage.all import*
from Crypto.Util.number import *

c = 
a = 
b = 
e=65537
zsm=Matrix(ZZ,[[a,1],[b,0]])
xq,pr=zsm.LLL()[0]
xq,pr=abs(xq),abs(pr)

for r in range(2**14,2**15):
   for x in range(50):
      p=pr+r
      q=x+xq
      n=p*q
      d=inverse(e,(p-1)*(q-1))
      m=pow(c,d,n)
      flag=long_to_bytes(m)
      if b'NSSCTF{' in flag:
        print(flag)
        break
```

### P4

task.py

```python

from Crypto.Util.number import *
from gmpy2 import *

flag = b'******'
flag = bytes_to_long(flag)

p = getPrime(1024)
r = getPrime(175)
a = inverse(r, p)
a = (a*flag) % p

print(f'a = {a}')
print(f'p = {p}')
```

$$
a\equiv r^{-1}flag \mod p \\
flag=ar+kp \\
\begin{pmatrix}
r&k
\end{pmatrix}
\begin{pmatrix}
a&2^{170}\\
p&0
\end{pmatrix}=
\begin{pmatrix}
flag&2^{170}r
\end{pmatrix}
$$

exp.sage

```python
from sage.all import*
from Crypto.Util.number import *

a = 
p = 
e=65537
zsm=Matrix(ZZ,[[a,2**170],[p,0]])
flag,R=zsm.LLL()[0]
flag,R=abs(flag),abs(R)

print(long_to_bytes(flag))
```

### P5

task.py

```python
from Crypto.Util.number import *
from gmpy2 import *

flag = b'******'
m = bytes_to_long(flag)

assert m.bit_length() == 351
p = getPrime(1024)
b = getPrime(1024)
c = getPrime(400)

a = (b*m + c) % p

print(f'a = {a}')
print(f'b = {b}')
print(f'p = {p}')
```

$$
c=a-bm+kp\\
\begin{pmatrix}
1&m&k
\end{pmatrix}
\begin{pmatrix}
a&0&2^{351}\\
-b&1&0\\
p&0&0
\end{pmatrix}=
\begin{pmatrix}
c&m&2^{351}
\end{pmatrix}
$$

exp.sage

```python
from sage.all import*
from Crypto.Util.number import *

a = 
b = 
p = 

zsm=Matrix(ZZ,[[a,0,2**351],[-b,1,0],[p,0,0]])
c,m,x=zsm.LLL()[0]
c,m,x=abs(c),abs(m),abs(x)

print(long_to_bytes(m))
```

### P6

task.py

```python
from Crypto.Util.number import *

flag = b'******'
flag = bytes_to_long(flag)
d = getPrime(400)

for i in range(4):
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = inverse(d, (p-1)*(q-1))
    c = pow(flag, e, n)
    print(f'e{i} =', e)
    print(f'n{i} =', n)
    print(f'c{i} =', c)
```

原型应该是`NUSTCTF 2022 新生赛`的一个论文题，[IJCSI-9-2-1-311-314](https://www.ijcsi.org/papers/IJCSI-9-2-1-311-314.pdf)  

具体实现方法是把最大的n开根号赋值给M，然后还有$e_id=1+k_i\phi N_i$，然后这里假设了phi可以写作`N-s`，使式子变成了
$$
e_id=1+k_i(N_i-s_i)\\
e_id-k_iN_i=1-k_is_i\\
我们还有一个式子dM=dM\\
可以写成矩阵相乘\\
\begin{pmatrix}
d & k_1 & k_2 & \dots & k_i
\end{pmatrix}
\begin{pmatrix}
M & e_1 & e_2 & \dots & e_i \\
0 & -N_1 & 0 & \dots & 0 \\
0 & 0 & -N_2 & \dots & 0 \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
0 & 0 & 0 & \dots & -N_i
\end{pmatrix}=
\begin{pmatrix}
dM & 1 - k_1 s_1 & 1 - k_2 s_2 & \dots & 1 - k_is_i
\end{pmatrix}
$$

exp.sage

```python
from Crypto.Util.number import *
from sage.all import*

M = isqrt(n0)

L = Matrix(ZZ, [[M, e0, e1, e2, e3],
                [0,-n0,  0,  0,  0],
                [0,  0,-n1,  0,  0],
                [0,  0,  0,-n2,  0],
                [0,  0,  0,  0,-n3]])

d = abs(L.LLL()[0][0]) // M

m = power_mod(c0, d, n0)

print(long_to_bytes(m))
```

### P7

task.py

```python
from Crypto.Util.number import *

flag = b'******'
flag = bytes_to_long(flag)

p = getPrime(512)
q = getPrime(512)
n = p * q
c = pow(flag, 65537, n)
print(f'n =', n)
print(f'c =', c)
for i in range(2):
    d = getPrime(350)
    e = inverse(d, (p-1)*(q-1))
    print(f'e{i} =', e)
```

这个其实就是维纳拓展攻击，从一元变成了二元，直接上脚本了

exp.sage

```python
from Crypto.Util.number import *
n = 
c = 
e0 = 
e1 = 
a = 5/14
D = diagonal_matrix(ZZ, [n, int(n^(1/2)), int(n^(1+a)), 1])
M = Matrix(ZZ, [[1, -n, 0, n^2],
                [0, e0, -e0, -e0*n],
                [0,  0, e1,  -e1*n],
                [0,  0,  0,  e0*e1]])*D
L = M.LLL()
t = vector(ZZ, L[0])
x = t * M^(-1)

x * M = t
phi = int(x[1]/x[0]*e0)

d = inverse_mod(65537, phi)
m = power_mod(c, d, n)
print(long_to_bytes(m))
```

### P8

task.py

```python
from Crypto.Util.number import *

flag = b'******'
m = bytes_to_long(flag)

p = getPrime(512)
s = [getPrime(32) for i in range(3)]
a = [getPrime(512) for i in range(3)]

c = (a[0]*s[0]**2*s[1]**2 + a[1]*s[0]*s[2]**2 + a[2]*s[1]*s[2]) % p

flag = m*s[0]*s[1]*s[2]
print(f'c = {c}')
print(f'flag = {flag}')
print(f'a = {a}')
print(f'p = {p}')
```

目的是求s，要对这个式子变形，想办法使未知量在一侧

$$
-s_1s_2=a_0a^{-1}_2s_0^{2}s_1^{2}+a_1a_2^{-1}s_0s_2^{2}-ca_2^{-1}+kp \\
\begin{pmatrix}
s_0^{2}s_1^{2}&s_0s_2^{2}&1&k
\end{pmatrix}
\begin{pmatrix}
a_0a^{-1}_2&0&0&1\\
a_1a_2^{-1}&0&1&0\\
-ca_2^{-1}&1&0&0\\
p&0&0&0
\end{pmatrix}=
\begin{pmatrix}
-s_1s_2&1&s_0s_2^{2}&s_0^{2}s_1^{2}
\end{pmatrix}
$$

发现直接这样打出不来，配平一下

exp.sage

```python
from Crypto.Util.number import *

c = 
flag = 
a = []
p = 

ia = inverse_mod(a[2], p)

L = Matrix(ZZ, [[a[0]*ia%p, 0, 0, 1],
                [a[1]*ia%p, 0, 1, 0],
                [-c*ia%p, 1, 0, 0  ],
                [p, 0, 0,         0]]) * diagonal_matrix(ZZ, [1, 2^32, 2^128, 2^64])

v = L.LLL()[0]
s0s1 = isqrt(abs(v[0]))
s1s2 = abs(v[3]) >> 64
s1 = gcd(s0s1, s1s2)
s0 = s0s1 // s1
s2 = s1s2 // s1

flag = flag // s0 // s1 // s2
print(long_to_bytes(flag))
```


## HNP问题

形式比较固定，一般长这样$k_i\equiv A_ix+B_i \mod p$，我们一般会有多组kAB，所以我们可以依靠这个去建格。  

这种式子经常出现在DSA签名中

$$
r \equiv g^k \mod q \\
s \equiv k^{-1}(H(m)+xr) \mod q \\
k_i \equiv s_i^{-1}r_ix+s_i^{-1}H(m) \mod q \\
A=s_i^{-1}r_i,B=s_i^{-1}H(m) \\
k_i=A_ix+B+l_iq
$$

这就是一个非常标准的HNP了，建一个格

$$
\begin{pmatrix}
l_1 & l_2 &  \dots & l_i &x & 1
\end{pmatrix}
\begin{pmatrix}
q & 0 & \dots & 0 & 0 & 0 \\
0 & 0 & \dots & 0 & 0 & 0\\
0 & 0 & \ddots & 0 & 0 & 0\\
\vdots & \vdots & \vdots & q & \vdots & \vdots\\
A_1 & A_2 & \dots & A_i & K/q & 0\\
B_1 & B_2 & \dots & B_i & 0 & K
\end{pmatrix}=
\begin{pmatrix}
k_1 & k_2  & \dots & k_i & Kx/q & K
\end{pmatrix}
$$

对应脚本
```python
import json

t = 40

# Load data
f = open("data", "r")
(q, Hm_s, r_s, s_s) = json.load(f)

# Calculate A & B
A = []
B = []
for r, s, Hm in zip(r_s, s_s, Hm_s):
    A.append( ZZ( (inverse_mod(s, q)*r) % q ) )
    B.append( ZZ( (inverse_mod(s, q)*Hm) % q ) )

# Construct Lattice
K = 2^122   # ki < 2^122
X = q * identity_matrix(QQ, t) # t * t
Z = matrix(QQ, [0] * t + [K/q] + [0]).transpose() # t+1 column
Z2 = matrix(QQ, [0] * (t+1) + [K]).transpose()    # t+2 column

Y = block_matrix([[X],[matrix(QQ, A)], [matrix(QQ, B)]]) # (t+2) * t
Y = block_matrix([[Y, Z, Z2]])

# Find short vector
Y = Y.LLL()

# check
k0 = ZZ(Y[1, 0] % q)
x = ZZ(Y[1, -2] / (K/q) % q)
assert(k0 == (A[0]*x + B[0]) % q)
print(x)

/**
* 复制并使用代码请注明引用出处哦~
* Lazzaro @ https://lazzzaro.github.io
*/
```

当然现在LCG的题目里面也有HNP了，比如LCG已知state高位求seed/LCG未知a,b求seed，这种题目在`0xGame`中是出现过的

### 1.2023闽盾杯

task.py

```python
from random import randbytes
from hashlib import sha256
from secret import FLAG

prime_q = 
prime_p = 2 * prime_q + 1
generator = 2

def generate_keys(prime_p:int, prime_q: int, generator: int):
    private_key = int(randbytes(48).hex(), 16)
    public_key = pow(generator, private_key, prime_p)
    return private_key, public_key

def signature(m: str, private_key: int):
    ephemeral_key = pow(int.from_bytes(m.encode(), "big"), -1, prime_q)
    value_r = pow(generator, ephemeral_key, prime_p) % prime_q
    hash_value = sha256(m.encode()).hexdigest()
    value_s = pow(ephemeral_key, -1, prime_q) * (int(hash_value, 16) + private_key * value_r) % prime_q
    return hash_value, value_r, value_s

def verification(message_hash: str, value_r: int, value_s: int, public_key: int):
    message_hash = int(message_hash, 16)
    inverse_s = pow(value_s, -1, prime_q)
    u1 = message_hash * inverse_s % prime_q
    u2 = value_r * inverse_s % prime_q
    value_v = (pow(generator, u1, prime_p) * pow(public_key, u2, prime_p) % prime_p) % prime_q
    return value_v == value_r

private_key, public_key = generate_keys(prime_p, prime_q, generator)
print(f"prime_p = {prime_p}")
print(f"prime_q = {prime_q}")
print(f"generator = {generator}")
print(f"public_key = {public_key}")
hash_value, value_r, value_s = signature(FLAG, private_key)
assert verification(hash_value, value_r, value_s, public_key)
print("FLAG= *******************************")
print(f"Here is your gift = {hash_value}")
print(f"value_r = {value_r}")
print(f"value_s = {value_s}")

```

先看看代码，可以看见他把flag加密完带进去当ephemeral_key了，按照上面的式子来说就是

$$
m=k^{-1},hash(m)=H\\
s\equiv k^{-1}\times (H+xr) \mod q \\
m=sH^{-1}-mxrH^{-1}+kq \\
sH^{-1}=B,-rH^{-1}=A,mx=t\\
m=At+B+kq\\
\begin{pmatrix}
k & t & 1
\end{pmatrix}
\begin{pmatrix}
q&0&0\\
A&1/2^{384}&0\\
B&0&2^{320}
\end{pmatrix}=
\begin{pmatrix}
m&t/2^{384}&2^{320}
\end{pmatrix}
$$

这边配平是因为只打格出不来，就改改，能跑出来就行()

exp.sage

```python
import gmpy2
from Crypto.Util.number import *

p = 
q = 
g = 2
pb = 
h = ''
r = 
s = 

H = int(h,16)
inv = gmpy2.invert(H,q)
A = -r*inv
B = s*inv

M = [[q,0,0],
      [A,1/2^384,0],
      [B,0,2^320]]

Ge = Matrix(M)

for i in Ge.LLL():
    if i[-1] == 2^320:
        m = i[0]
        print(long_to_bytes(int(m)))
```

### 2.BabyHNP

task.py

```python
from secret import flag
from random import randint
import libnum
import os
assert len(flag) == 44

def padding(f):
    return f + os.urandom(64 - 1 - len(f))

n = 5
m = libnum.s2n(padding(flag))
q = libnum.generate_prime(512)
A = [randint(1, q) for i in range(n)]
B = [A[i] * m % q for i in range(n)]
b = [B[i] % 2**128 for i in range(n)]

print('q = %s' % q)
print('A = %s' % A)
print('b = %s' % b)
```

$$
B_i=b_i+k\times 2^{128} \\
b_i+k_i\times 2^{128}\equiv A_im \mod q \\
k_i=A_im\times (2^{-128} \mod q)-b_i\times (2^{-128} \mod q)+l_iq
$$

这个就和上面的格一模一样了，直接构建就行了

exp.sage

```python
from gmpy2 import *
from Crypto.Util.number import *

p = 
B = [, , , , ]
R = [, , , , ]


n = len(R)

M = Matrix(QQ,n+2,n+2)
inv = invert(2 ** 128,p)

for i in range(n):
    M[i,i] = p
    M[-2,i] = B[i] * inv
    M[-1,i] = -R[i] * inv

t = 1 / 2^128
K = 2^384

M[-2,-2] = t
M[-1,-1] = K

L = M.LLL()

x = L[1][-2] // t
m = x % p
print(int(m).bit_length())
print(long_to_bytes(int(m)))
```

看了好多师傅的博客，感觉HNP都可以建成这个格，主要难的还是化简构造，得自己多练练，找到这种建格去打的感觉才行

## HSP&HSSP

HSP在我的认知里就是背包的升级版？或者说背包就是一种HSP，而HSSP是一种正交格，这个真的不会，看[Tover](https://tover.xyz/p/HSSP-note/)神的博客吧，我只会套脚本

## LWE

这种问题的特点在于有一个噪音e(一般比较小)，比如原式子是$Ax=b$，加入噪音之后变成了$Ax+e=b$，在未知x和e的情况下，我们就可以通过建格去先求出e，然后解方程求出x，构建这个格就行了
$$
\begin{pmatrix}
A &0\\
-b&1
\end{pmatrix}
$$

### SUSCTF2022

task.py

```python
import numpy as np
from secret import flag

def gravity(n,d=0.25):
    A=np.zeros([n,n])
    for i in range(n):
        for j in range(n):
            A[i,j]=d/n*(d**2+((i-j)/n)**2)**(-1.5)
    return A

n=len(flag)
A=gravity(n)
x=np.array(list(flag))
b=A@x
np.savetxt('b.txt',b)
```

b已经给出，那么可以知道矩阵的维度，那么就可以恢复出A，再按照上面的格去打出e就行了

exp.sage

```python
import numpy as np

def gravity(n,d=0.25):
    A=np.zeros([n,n])
    for i in range(n):
        for j in range(n):
            A[i,j]=d/n*(d**2+((i-j)/n)**2)**(-1.5)
    return A

b = []
for i in open('b.txt','r').readlines():
    b.append(float(i.strip()))

n = 85
A = gravity(85)

t = 10^21
for i in range(len(b)):
    b[i] = -b[i] * t
    
for i in range(n):
    for j in range(n):
        A[i,j] = A[i,j] * t

M = Matrix(ZZ,n+1,n+1)

for i in range(n):
    M[-1,i] = b[i]
    for j in range(n):
        M[i,j] = A[i,j]

M[-1,-1] = 1

e = M.LLL()[0]
flag = M.solve_left(e)

print(bytes(flag[:-1]))
```

### 常用脚本
这里直接搬la佬的了

```
#脚本1-小规模
#Sage
from sage.modules.free_module_integer import IntegerLattice

row = 
column = 
prime = 

ma = 
res = 

W = matrix(ZZ, ma)
cc = vector(ZZ, res)

# Babai's Nearest Plane algorithm
def Babai_closest_vector(M, G, target):
    small = target
    for _ in range(5):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -=  M[i] * c
    return target - small

A1 = matrix.identity(column)
Ap = matrix.identity(row) * prime
B = block_matrix([[Ap], [W]])  
lattice = IntegerLattice(B, lll_reduce=True)
print("LLL done")
gram = lattice.reduced_basis.gram_schmidt()[0]
target = vector(ZZ, res)
re = Babai_closest_vector(lattice.reduced_basis, gram, target)
print("Closest Vector: {}".format(re))

R = IntegerModRing(prime)
M = Matrix(R, ma)
M = M.transpose()

ingredients = M.solve_right(re)
print("Ingredients: {}".format(ingredients))

m = ''
for i in range(len(ingredients)):
    m += chr(ingredients[i])
print(m)
```

```
#脚本2-大规模
#Sage
from sage.modules.free_module_integer import IntegerLattice
from random import randint
import sys
from itertools import starmap
from operator import mul

# Babai's Nearest Plane algorithm
# from: http://mslc.ctf.su/wp/plaidctf-2016-sexec-crypto-300/
def Babai_closest_vector(M, G, target):
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

m = 
n = 
q = 

A_values = 
b_values = 

A = matrix(ZZ, m + n, m)
for i in range(m):
    A[i, i] = q
for x in range(m):
    for y in range(n):
        A[m + y, x] = A_values[x][y]
lattice = IntegerLattice(A, lll_reduce=True)
print("LLL done")
gram = lattice.reduced_basis.gram_schmidt()[0]
target = vector(ZZ, b_values)
res = Babai_closest_vector(lattice.reduced_basis, gram, target)
print("Closest Vector: {}".format(res))

R = IntegerModRing(q)
M = Matrix(R, A_values)
ingredients = M.solve_right(res)

print("Ingredients: {}".format(ingredients))

for row, b in zip(A_values, b_values):
    effect = sum(starmap(mul, zip(map(int, ingredients), row))) % q
    assert(abs(b - effect) < 2 ** 37)

print("ok")
```