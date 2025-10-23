---
title: 强网杯2024_crypto
published: 2024-12-12
pinned: false
description: 强网杯2024，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2024-12-12
pubDate: 2024-12-12
---


## 前言
一共七题，出了三个，但是海鲜市场上面已经py烂了，我该喜还是该忧呢？在这里就只写上自己已经出了的题，其他的慢慢复现，最近期中考试+香港比较忙。

## 题目
### EzRsa
task
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import random, gmpy2

class RSAEncryptor:
	def __init__(self):
		self.g = self.a = self.b = 0
		self.e = 65537
		self.factorGen()
		self.product()

	def factorGen(self):
		while True:
			self.g = getPrime(500)
			while not gmpy2.is_prime(2*self.g*self.a+1):
				self.a = random.randint(2**523, 2**524)
			while not gmpy2.is_prime(2*self.g*self.b+1):
				self.b = random.randint(2**523, 2**524)
			self.h = 2*self.g*self.a*self.b+self.a+self.b
			if gmpy2.is_prime(self.h):
				self.N = 2*self.h*self.g+1
				print(len(bin(self.N)))
				return

	def encrypt(self, msg):
		return gmpy2.powmod(msg, self.e, self.N)


	def product(self):
		with open('/flag', 'rb') as f:
			self.flag = f.read()
		self.enc = self.encrypt(self.flag)
		self.show()
		print(f'enc={self.enc}')

	def show(self):
		print(f"N={self.N}")
		print(f"e={self.e}")
		print(f"g={self.g}")


RSAEncryptor()
```

思路：
重点代码是
$$ h=2gab+a+b $$ 和 $$ N=2hg+1  $$,我们讲$$N$$直接展开,其实就是$$ N=(2ga+1)(2gb+1)  $$,这个就是老熟人了，Common Prime Rsa,可以参考[独奏](https://hasegawaazusa.github.io/common-prime-rsa.html "独奏")的文章，易知是 $$g<a+b$$ 的类型,我们之间修改模板就行了。

exp
```
from sage.groups.generic import bsgs
from Crypto.Util.number import *
from pwn import*
import gmpy2
from sympy import primerange
p=remote('47.94.226.70', 32973)

e=65537

N=p.recvline().decode().split('=')[1]
e=p.recvline().decode().split('=')[1]
g=p.recvline().decode().split('=')[1]
enc=p.recvline().decode().split('=')[1]
N=int(N)
e=int(e)
g=int(g)
enc=int(enc)
print(N)
print(e)
print(g)
print(enc)

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
    print(p)
    print(q)
    phi=(p-1)*(q-1)
    d=gmpy2.invert(e,phi)
    m=pow(enc,d,N)
    print(long_to_bytes(m))
```

因为bsgs现在很慢，几乎被抛弃了，可以使用discrete_log_lambda,大概三秒跑出flag。

### apbq
task
```
from Crypto.Util.number import *
from secrets import flag
from math import ceil
import sys

class RSA():
    def __init__(self, privatekey, publickey):
        self.p, self.q, self.d = privatekey
        self.n, self.e = publickey

    def encrypt(self, plaintext):
        if isinstance(plaintext, bytes):
            plaintext = bytes_to_long(plaintext)
        ciphertext = pow(plaintext, self.e, self.n)
        return ciphertext

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, bytes):
            ciphertext = bytes_to_long(ciphertext)
        plaintext = pow(ciphertext, self.d, self.n)
        return plaintext

def get_keypair(nbits, e = 65537):
    p = getPrime(nbits//2)
    q = getPrime(nbits//2)
    n = p * q
    d = inverse(e, n - p - q + 1)
    return (p, q, d), (n, e)

if __name__ == '__main__':
    pt = './output.txt'
    fout = open(pt, 'w')
    sys.stdout = fout

    block_size = ceil(len(flag)/3)
    flag = [flag[i:i+block_size] for i in range(0, len(flag), block_size)]
    e = 65537

    print(f'[+] Welcome to my apbq game')
    # stage 1
    print(f'┃ stage 1: p + q')
    prikey1, pubkey1 = get_keypair(1024)
    RSA1 = RSA(prikey1, pubkey1)
    enc1 = RSA1.encrypt(flag[0])
    print(f'┃ hints = {prikey1[0] + prikey1[1]}')
    print(f'┃ public key = {pubkey1}')
    print(f'┃ enc1 = {enc1}')
    print(f'----------------------')

    # stage 2
    print(f'┃ stage 2: ai*p + bi*q')
    prikey2, pubkey2 = get_keypair(1024)
    RSA2 = RSA(prikey2, pubkey2)
    enc2 = RSA2.encrypt(flag[1])
    kbits = 180
    a = [getRandomNBitInteger(kbits) for i in range(100)]
    b = [getRandomNBitInteger(kbits) for i in range(100)]
    c = [a[i]*prikey2[0] + b[i]*prikey2[1] for i in range(100)]
    print(f'┃ hints = {c}')
    print(f'┃ public key = {pubkey2}')
    print(f'┃ enc2 = {enc2}')
    print(f'----------------------')

    # stage 3
    print(f'┃ stage 3: a*p + q, p + bq')
    prikey3, pubkey3 = get_keypair(1024)
    RSA3 = RSA(prikey3, pubkey3)
    enc3 = RSA2.encrypt(flag[2])
    kbits = 512
    a = getRandomNBitInteger(kbits)
    b = getRandomNBitInteger(kbits)
    c1 = a*prikey3[0] + prikey3[1]
    c2 = prikey3[0] + b*prikey3[1] 
    print(f'┃ hints = {c1, c2}')
    print(f'┃ public key = {pubkey3}')
    print(f'┃ enc3 = {enc3}')
```

#### part1
已知$$pq=n,p+q=hints$$,直接利用sympy解方程就可以了
exp
```
c=
pq = 
n=
e=65537

from Crypto.Util.number import *
from sympy import*

p, q = symbols('p q')
eq1 = Eq(p+q, pq)
eq2 = Eq(p*q, n)
sol = solve((eq1, eq2), (p, q))
print(sol)

p=
q=
phi=(p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

#### part2
已知$$h=ap+bq$$,而且有一百组，pq都是512bits，而ab是180bits，有这样小的数，我们就可以想到用格，因为自己太菜，直接找到了ductf2023年的exp，改成一百组，就直接出来了（好像四组就行）
exp
```
import itertools
from Crypto.Util.number import long_to_bytes, GCD
from sage.all import Matrix, ZZ, QQ, ideal

hints = 

n = 
e = 65537
c = 

V = hints
k = 2**400
M = Matrix.column([k * v for v in V]).augment(Matrix.identity(len(V)))
B = [b[1:] for b in M.LLL()]
M = (k * Matrix(B[:len(V)-2])).T.augment(Matrix.identity(len(V)))
B = [b[-len(V):] for b in M.LLL() if set(b[:len(V)-2]) == {0}]

for combination in itertools.product(range(101), repeat=2):
    T = combination[0] * B[0] + combination[1] * B[1]
    a = T[:len(V)]
    kq = GCD(a[1] * hints[0] - a[0] * hints[1], n)
    if 1 < kq < n:
        print('find!', kq, combination[0], combination[1])
        break

for i in range(2**16, 1, -1):
    if kq % i == 0:
        kq //= i
q = int(kq)
p = int(n // kq)
print(p, q)

```

#### part3
写了一个小时，然后发现用的第二组密钥加密的，真的难崩
正确写法可以参考这个[帖子](https://github.com/defund/ctf/blob/master/angstromctf-2024/blahaj/solve.sage "帖子")

### 21step
task
```
import re
import random
from secrets import flag
print(f'Can you weight a 128 bits number in 21 steps')
pattern = r'([AB]|\d+)=([AB]|\d+)(\+|\-|\*|//|<<|>>|&|\^|%)([AB]|\d+)'

command = input().strip()
assert command[-1] == ';'
assert all([re.fullmatch(pattern, i) for i in command[:-1].split(';')])

step = 21
for i in command[:-1].split(';'):
    t = i.translate(str.maketrans('', '', '=AB0123456789'))
    if t in ['>>', '<<', '+', '-', '&', '^']:
        step -= 1
    elif t in ['*', '/', '%']:
        step -= 3
if step < 0:exit()

success = 0
w = lambda x: sum([int(i) for i in list(bin(x)[2:])])
for _ in range(100):
    A = random.randrange(0, 2**128)
    wa = w(A)
    B = 0
    try : exec("global A; global B;" + command)
    except : exit()
    if A == wa:
        success += 1

if success == 100:
    print(flag)
```

思路：很直接的题目，一个128bits的数，在21步算出他二进制中一的数量，直接找到Integer的类型源码，改成128位就好了

exp
```
from pwn import *

io = remote('39.107.90.219', 22677)
command = 'B=A>>1;B=B&113427455640312821154458202477256070485;A=A-B;B=A>>2;B=B&68056473384187692692674921486353642291;A=A&68056473384187692692674921486353642291;A=A+B;B=A>>4;A=A+B;A=A&20016609818878733144904388672456953615;B=A>>8;A=A+B;B=A>>16;A=A+B;B=A>>32;A=A+B;B=A>>64;A=A+B;A=A&127;'
io.recvuntil(b'Can you weight a 128 bits number in 21 steps')
for i in range(100):
    io.sendline(command)

io.recvline()
io.interactive()
```

## 总结
没有爆零！！！其他的慢慢复现更新