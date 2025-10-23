---
title: Moectf 强壮密码人部分题解
published: 2025-08-21
pinned: false
description: moectf crypto wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-08-21
pubDate: 2025-08-21
---


## 前言

打moectf的时候顺便看了看训练场的强壮密码人，题目还不错，写一下。

## 题目

### 0rsa0

task.py

```python
from Crypto.Util.number import *
from flag import flag

assert flag[0:7] == b'moectf{'
assert flag[-1:] == b'}'
flag = flag[7:-1]
assert len(flag) == 32

m1 = bytes_to_long(flag[0:16])
m2 = bytes_to_long(flag[16:32])

def enc1(m):
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 3
    c = pow(m,e,n)
    return n,e,c

def enc2(m):
    p = getPrime(512)
    q = getPrime(512)
    e = 65537
    d = inverse(e,(p-1)*(q-1))
    n = p * q 
    dp2 = d % (p-1)
    c = pow(m,e,n)
    return n,e,c,dp2

n1,e1,c1 = enc1(m1)
n2,e2,c2,dp2 = enc2(m2)

print("n1="+ str(n1))
print("e1="+ str(e1))
print("c1="+ str(c1))
print("n2="+ str(n2))
print("e2="+ str(e2))
print("c2="+ str(c2))
print("dp2="+ str(dp2))
```

思路：
+ m1就是简单的`小e攻击`，一般开三次方，如果$m^e>n$就要小范围爆破一下.
+ m2就更明显了，dp攻击bro，直接遍历e，去看`p=(dp * e - 1) // i + 1`，然后算flag就行了.

exp.py 

```python
from Crypto.Util.number import *
from gmpy2 import *

n1=
e1=3
c1=
n2=
e2=65537
c2=
dp2=

m1=iroot(c1,3)[0]
print(long_to_bytes(m1))

a = getPrime(10)

p = GCD(pow(a,dp2*e2,n2)-a,n2)
m2 = pow(c2,dp2,p)
print(long_to_bytes(m2))

flag=b'moectf{'+long_to_bytes(m1)+long_to_bytes(m2)+b'}'
print(flag)
```

### BBBBBBBackpack

task.py 

```python
from Crypto.Util.number import*
import random

flag = xxxxx
m = bytes_to_long(flag)

backpack = [1]
for i in range(160):
    backpack = backpack + [random.randrange(backpack[-1]*2,backpack[-1]*4)]
print(backpack)

backpack = backpack[::-1]
l_list = []
for i in backpack:
    l_list.append(m//i)
    m = m % i 
print(l_list)
print(m)
```

思路：超序列化背包

exp.py 

```python
from Crypto.Util.number import *

m_list=
m=
m_list = list(m_list[::-1])
n = len(m)
flag = 0
for i in range(n):
    flag += m_list[i]*m[i]

print(long_to_bytes(flag))
```

### BabyMultiple

task.py 

```python
def encode(msg,mul):
    c = b''
    for i in msg:
        index = table.find(i)
        index_after = (index * mul) % 63
        c = c + bytes.fromhex(hex(table[index_after])[2:])
    return c

table = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
FLAG = xxxxx

assert len(table) == 63
assert FLAG[:7] == b'moectf{'
assert FLAG[-1:] == b'}'

Mul = 58
msg = FLAG[7:-1]

c = encode(msg,Mul)
print(c)

#b'g3AfJPOfHPOJFfJuf_AYux1JFx39'
```

思路：`i*58 mod 63`加密的，逆回去学

exp.py 

```python
table = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
c = b'g3AfJPOfHPOJFfJuf_AYux1JFx39'
Mul = 58
mod = len(table)

Mul_inv = pow(Mul, -1, mod) 

def decode(cipher_text, mul_inv):
    msg = b''
    for i_byte in cipher_text:
        index_after = table.find(i_byte)
        original_index = (index_after * mul_inv) % mod
        msg += table[original_index:original_index+1]
        
    return msg

decrypted_msg = decode(c, Mul_inv)
FLAG = b'moectf{' + decrypted_msg + b'}'

print(FLAG)
```

### LazyRSA

task.py 

```python
from Crypto.Util.number import*

p = getPrime(512)
q = getPrime(512)

n = p*q
e = 0x10001

flag = xxx
m = bytes_to_long(flag)

c = pow(m,e,n)
print("p = " , p)
print("q = " , q)
print("c = " , c)
```

思路：直接算就行

exp.py 

```python
from Crypto.Util.number import *

p =  
q =  
c =  

print(long_to_bytes(pow(c,inverse(65537,(p-1)*(q-1)),p*q)))
```

### Little_FSR

task.py 

```python
import random
import string

from Crypto.Util.number import *
from gmpy2 import *
from secret import FLAG, key

assert FLAG[:7] == b'moectf{'
assert FLAG[-1:]== b'}'
table = string.ascii_letters+string.digits+string.punctuation
for _ in range(50-len(FLAG)):
    FLAG += random.choice(table).encode()
assert len(FLAG) == 50
assert len(key) == 5

class LFSR:
    def __init__(self):
        self.data = list(map(int,list(bin(bytes_to_long(FLAG))[2:].rjust(400,'0'))))
        for _ in range(2022):
            self.cycle()

    def cycle(self):
        bit = self.data[0]
        new = 0
        for i in key:
            new ^= self.data[i]
        self.data = self.data[1:] + [new]
        return bit

ILOVEMOECTF = LFSR()
for _ in range(2022):
    print(ILOVEMOECTF.cycle(), end='')
```

思路：表面FSR实际效果和LFSR差不多

```python
class lfsr():
    def __init__(self, init, mask, length):
        self.init = init
        self.mask = mask
        self.lengthmask = 2**(length+1)-1

    def next(self):
        nextdata = (self.init << 1) & self.lengthmask 
        i = self.init & self.mask & self.lengthmask 
        output = 0
        while i != 0:
            output ^= (i & 1)
            i = i >> 1
        nextdata ^= output
        self.init = nextdata
        return output
```

加密方式是

$$
newbit = data_{key[0]}\bigoplus data_{key[1]}\bigoplus \cdots \bigoplus data_{key[m]}
$$

按理来说可以爆破？时间太长了，我们这里求解线性同余方程组

```python
from Crypto.Util.number import *

data =
b = list(data[400:800])
B =vector(Zmod(2),b)
mt = matrix(Zmod(2),0,400)
for i in range(400):
    mt = mt.stack(vector(Zmod(2),list(data[i:i+400])))
x = mt \ B
key = []
for index,i in enumerate(x):
    if i == 1:
        key.append(index)
print(key)
# [8, 23, 114, 211, 360]

Len = 400 - key[0]
m = list(map(int,data[:Len]))

for _ in range(2022):
    c = 0
    for t in key: c = c^^m[t-key[0]-1]
    m = [c] + m[:Len-1]

flag = ''.join(str(i) for i in m)


print(long_to_bytes(int(flag,2)))
```

### MiniMiniBackPack

task.py 

```python
from gmpy2 import *
from Crypto.Util.number import *
import random
from FLAG import flag

def gen_key(size):
    s = 1000
    key = []
    for _ in range(size):
        a = random.randint(s + 1, 2 * s)
        assert a > sum(key)
        key.append(a)
        s += a
    return key


m = bytes_to_long(flag)
L = len(bin(m)[2:])
key = gen_key(L)
c = 0

for i in range(L):
    c += key[i]**(m&1)
    m >>= 1

print(key)
print(c)
```

思路：贪心求解即可：从大到小，如果可以减去当前大数，则减去，并且对应二进制明文为1 

exp.py 

```python
from Crypto.Util.number import *
key=[]
c = 

m = ''
for i in reversed(key):
    if c > i:
        m += '1'
        c -= i
    else:
        m += '0'
        c -= 1


flag = long_to_bytes(int(m,2))
print(flag)
```

### NumberTheory-FeeeeeMa

task.py 

```python
import gmpy2
from Crypto.Util.number import *

p = getPrime(2048) 
q = gmpy2.next_prime(p)
for i in range(3600):
    if i%100 ==0:
        print(i)
    q = gmpy2.next_prime(q)

n = p * q
e = 0x10001

flag = xxx
m = bytes_to_long(flag)
c = pow(m,e,n)
print(c)
print(n)
```

思路：肉眼可见的两个值离得近，这里直接`iroot`开方，发现离的有点远，费马分解梭哈

exp.py 

```python
from Crypto.Util.number import *
from gmpy2 import *

c=
n=
e=0x10001

def fermat_factor(n):
    a = gmpy2.isqrt(n) + 1

    while True:
        b2 = gmpy2.square(a) - n
 
        if gmpy2.is_square(b2):
            b = gmpy2.isqrt(b2)
            p = a - b
            q = a + b
            return p, q

        a += 1

def solve():

    p, q = fermat_factor(n)
    

    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m = pow(c, d, n)
    
    flag = long_to_bytes(m)
    print(flag) 

if __name__ == '__main__':
    solve()
```

### NumberTheory-MyGrandson

task.py 

```python
import random

from Crypto.Util.number import *

prime_list = []
while len(prime_list) != 10:
    p = getPrime(512)
    if p not in prime_list:
        prime_list.append(p)

n_list = []
while len(prime_list) != 0 :
    p = random.choice(prime_list)
    prime_list.remove(p)
    q = random.choice(prime_list)
    prime_list.remove(q)
    n = p * q
    n_list.append(n)

e = 0x3
flag = xxxx
m = bytes_to_long(flag)

c_list = []
for i in range(5):
    c_list.append(pow(m,e,n_list[i]))

print(n_list)
print(c_list)
```

思路：经典crt问题，crt求解后开三次方即可

```python
from Crypto.Util.number import *
from gmpy2 import *
from sage.all import *

n_list=
c_list=
e=3

m_cubed = crt(c_list, n_list)
m=iroot(m_cubed,e)[0]
print(long_to_bytes(m))
```

### NumberTheory-Powwwwwer

task.py 

```python
from Crypto.Util.number import *

p = getPrime(512)
q = getPrime(512)

flag = xxxxx
m = bytes_to_long(flag)
n = p * q
e1 = 0x114514
e2 = 11451401

c1 = pow(m,e1,n)
c2 = pow(m,e2,n)
print(c1)
print(c2)
print(n)
```

思路：经典的共模攻击

$$ 
c_1=m^{e_1} \mod n \\
c_2=m^{e_2} \mod n \\
由欧几里得算法可知e_1x+e_2y=1 \\
那么 c^{x}\times c^{y}=m^{xe_1+ye_2}=m \mod n
$$

exp.py 

```python
from Crypto.Util.number import*
import gmpy2

c1=
c2=
n=
e1 = 0x114514
e2 = 11451401


r,s1,s2 = gmpy2.gcdext(e1, e2)
m = (pow(c1,s1,n)*pow(c2,s2,n)) % n
print(long_to_bytes(m))
```

### PRintNewG

task.py 

```python
import random
from Crypto.Util.number import*
from FLAG import flag

class PRintNewG:
    def __init__(self,seed):
        self.state = seed
        self.a = random.randint(2**256,2**257)
        self.b = random.randint(2**256,2**257)
        if self.b > self.a:
            self.b = self.b - self.a
        self.n = getPrime(257)

    def NewG(self):
        self.state = (self.a * self.state + self.b) % self.n
        print(self.state)

PrintNewG = PRintNewG(bytes_to_long(flag))
print(PrintNewG.n)
PrintNewG.NewG()
PrintNewG.NewG()
PrintNewG.NewG()
```

思路：就是LCG，知道n，知道连续三次输出，这里直接求解

exp.py 

```python
from Crypto.Util.number import *
n = 164955381960104851576442781839629371483790790743830073857213053104860144345367
s1 = 67066424717605861916529090048670931008913194546199003522357504998012803616537
s2 = 14585402872351563180055857554749250191721167730349724393021149201170995608751
s3 = 68393939370424772490169906192546208899639826391163845848999554903218827210979

def solve_lcg():
    s2_minus_s1_inv = pow(s2 - s1, -1, n)
    a = ((s3 - s2) * s2_minus_s1_inv) % n

    b = (s2 - a * s1) % n

    a_inv = pow(a, -1, n)
    s0 = ((s1 - b) * a_inv) % n
    flag = long_to_bytes(s0)
    print(flag) 
if __name__ == '__main__':
    solve_lcg()
```

### Signin

task.py 

```python
from Crypto.Util.number import *
from secret import flag
m=bytes_to_long(flag)
p=getPrime(512)
q=getPrime(512)
print('p=',p)
print('q=',q)
n=p*q
e=65537
c=pow(m,e,n)
print('c=',c)
```

思路：有个小坑，q和e不互素的

exp.py 

```python
from Crypto.Util.number import *

p= 
q= 
c= 
e=65537

print(GCD(e,p-1))

print(long_to_bytes(pow(c,inverse(e,p-1),p)))
```

### Weird_E_Revenge

task.py 

```python
from Crypto.Util.number import *
import random
from secret import flag
table='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
pad=100-len(flag)
for i in range(pad):
    flag+=random.choice(table).encode()
e=343284449
m=bytes_to_long(flag)
assert m>(1<<512)
assert m<(1<<1024) 
p=getPrime(512)
q=getPrime(512)
r=getPrime(512)
print('p=',p)
print('q=',q)
print('r=',r)
n1=p*q
n2=q*r
c1=pow(m,e,n1)
c2=pow(m,e,n2)
print('c1=',c1)
print('c2=',c2)
```

思路：应该都差不多，`m1=m mod p,m2=m mod r`

$$
m=m_1\cdot r\cdot inv_1+m_2\cdot p \cdot inv_2 \\
其中 inv_1\equiv r^{-1}(mod\ p),inv_2\equiv p^{-1}(mod\ r)
$$

还有一个思路(在github看见的)

$x\equiv c1(\mod n1)$<br>
$x\equiv c2(\mod n2)$

这里的x表示什么呢？我们知道两个密文都是由 $m^e$ 模各自的n得到的，所以x就是 $m^e$ 。crt求解就可以得到 $m^e$ 的一个特解。

但是求完还是有问题。e值没有改变，还是那么大，意味着无法爆破或者有限域开根。必须要找到d，们把模数换成p*r。

$result\equiv x=m^e\%p(\mod p)$<br>
$result\equiv x=m^e\%r(\mod r)$

把q去掉，拿刚刚求出的特解再次构造同余方程组。这个同余方程组求出来的特解 $result\equiv m^e (\mod p*r)$ 。

可以这么想，设 $a\equiv m^e\%p(\mod p),b\equiv m^e\%r(\mod r)$ ，那么a\*b必定是这个同余方程组的解之一。

$a=k1\times p+m^e,b=k2\times r+m^e$ ，

那么 $ab=(k1p+m^e)\times (k2r+m^e)=k1\times k2\times pr+k1pm^e+k2rm^e+m^a,a=2e$ 。 

$k1\times k2\times pr+k1pm^e+k2rm^e$ 这段模pr余数肯定是0

exp.py 

```python
from Crypto.Util.number import *
from sympy.ntheory.modular import crt

p= 
q= 
r= 
c1= 
c2= 
e=343284449
n1=p*q
n2=q*r
n3=p*r
m=crt([n1,n2],[c1,c2])[0]
m1=m%p
m3=m%r
m=crt([p,r],[m1,m3])[0]
d=inverse(e,(p-1)*(r-1))
print(long_to_bytes(pow(m,d,n3)))
```

### beginOfCrypto

task.py 

```python
import math
flag = xxx

data = list(map(ord,flag))
cip = []
for i in range(len(data)):
    cip.append(math.e**data[i])
print(cip)
```

思路：就是次方了，直接log求解

exp.py 

```python
import math

cip = []

flag = ""
for c in cip:
    ascii_val = math.log(c)
    rounded_ascii = round(ascii_val)
    flag += chr(rounded_ascii)

print(flag)
```

### ezRSA

task.py 

```python
from Crypto.Util.number import *

flag = bytes_to_long(xxxxx)
p,q,r = getPrime(2048),getPrime(2048),getPrime(2048)
n = p * q * r
e = 0x10001

s = getPrime(300)
print(160 * s ** 5 - 4999 * s ** 4 + 3 * s ** 3 +1)

gift = (pow(p, (q-1)*(r-1)*q*r, (q*r) ** 3)* pow(q*r+1, q, (q*r)**3)) % (q*r)**3
print(gift)

phi = (p-1)*(q-1)*(r-1)
d = inverse(e,phi)
k = (p-s)*d
enc = pow(flag,e,n)
print(n)
print(k)
print(enc)
```

思路：叔论题，gift推导了一堆，正经方法是先拿到s 

$$
3^{ek}\mod n - 3^{1-s}\mod n =3^{p-s}\mod n -3^{1-s}\mod n 
$$

可以拿到p，接着求qr，这里稍微推一下`gift mod q^2*r^2`，

$$ 
gift = p^{q(q-1)r(r-1)}(qr+1)^q = (qr+1)^q=(q^2r+1) \mod (qr)^2 
$$

那么就可以求解出来了

不正经的方法：`gift-1`和n做gcd即可

exp.py 

```python
from Crypto.Util.number import *

gift=
e=65537
n=
enc=
qr=GCD(gift-1,n)
p=n//qr

print(long_to_bytes(pow(enc,inverse(e,p-1),p)))
```

### ez_cbc

task.py 

```python
from Crypto.Util.number import *
import random
from secret import flag

IV = bytes_to_long(b'cbc!') 
K = random.randrange(1,1<<30)

assert flag[:7] == b'moectf{'
assert flag[-1:] == b'}'

block_length = 4
flag = flag + ((block_length - len(flag) % block_length) % block_length) * b'\x00'
plain_block = [flag[block_length * i: block_length * (i + 1)] for i in range(len(flag) // block_length)]

c = []
c0 = (IV ^ bytes_to_long(plain_block[0])) ^ K
c.append(c0)

for i in range(len(plain_block)-1):
    c.append(c[i] ^ bytes_to_long(plain_block[i+1]) ^ K)

print(c)
```

exp.py 

```python
from Crypto.Util.number import *

c = []

IV = bytes_to_long(b'cbc!')
p0_long = bytes_to_long(b'moec')

plain_longs = [p0_long]

p1_long = p0_long ^ IV ^ c[1]
plain_longs.append(p1_long)

for i in range(1, len(c) - 1):
    pi = plain_longs[i]
    ci_minus_1 = c[i - 1]
    ci_plus_1 = c[i + 1]
    
    pi_plus_1 = pi ^ ci_minus_1 ^ ci_plus_1
    plain_longs.append(pi_plus_1)

padded_flag = b''
for p_long in plain_longs:
    padded_flag += long_to_bytes(p_long, 4)

flag = padded_flag[:padded_flag.rfind(b'}') + 1]

print(flag.decode())
```

### smooth

task.py 

```python
from Crypto.Util.number import sieve_base,isPrime,getPrime
import random
from secret import flag

def get_vulnerable_prime():
    p=2
    while True:
        for i in range(136):
            smallp=random.choice(sieve_base)
            p*=smallp
        if isPrime(p+1):
            return p+1

P=get_vulnerable_prime()
Q=getPrime(2048)
N=P*Q
e=0x10001

for i in range(1,P-1729):
    flag=flag*i%P

c=pow(flag,e,N)
print("c=",hex(c))
print("N=",hex(N))
```

思路：明显的p-1光滑，可以分解出来pq，然后有个Wilson定理，$(p-1)! \equiv -1 \pmod p$ 

exp.py 

```python
from Crypto.Util.number import *
from gmpy2 import *

c= 
N= 

def p_1_smooth(N):
    a = 2;n = 2
    while True:
        a = pow(a, n, N)
        res = GCD(a-1, N)
        if res != 1 and res != N:
            return res
        n += 1

p=p_1_smooth(N)
q=N//p
phi=(p-1)*(q-1)
d=inverse(0x10001,phi)
m=pow(c,d,N)

for i in range(p-1729,p):
    m=m*i%p
m=(-m)%p

print(long_to_bytes(m))
```

### 一次就好

task.py 

```python
from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
from gmpy2 import powmod,next_prime
from FLAG import flag
import codecs

c = b'Just once,I will accompany you to see the world'
flag = flag.ljust(len(c),'#')
key = strxor(flag.encode(), c)
m = bytes_to_long(key)

p = getPrime(512)
q = next_prime(p)
N = p*q
e = 0x10001

gift = powmod(m, e, N)

print(gift)
print(N)
```

思路：先开方求出pq，最后有个xor

exp.py 

```python
from Crypto.Util.number import *
from Crypto.Util.strxor import strxor
from gmpy2 import *

gift = 
N = 
e=65537
c = b'Just once,I will accompany you to see the world'
p=iroot(N,2)[0]
p=next_prime(p)
q=N//p
assert p*q==N
flag=long_to_bytes(pow(gift,inverse(e,(p-1)*(q-1)),N),len(c))
flag=strxor(flag,c)
print(flag)
```

### 不止一次

这个比较谜语人，我们知道flag头是什么，加密主要是一个key对不同的密文加密，后面发现每个都差不多，爆破一下就行了

exp.py 

```python
from Crypto.Util.strxor import strxor
from string import printable

A = bytes.fromhex("")
B = bytes.fromhex("")

known = "moectf{"
flag_len = 36
while len(known) < flag_len:
    for c in printable:
        flag = known + c + "a"*(flag_len - 1 - len(known))
        flag = flag.encode()
        a = strxor(A,flag)
        b = strxor(B,flag)
        if a[len(known)] == b[len(known)-1]:
            known+=c
            break
```

### 马锤壳s 

task.py 

```python
from sage.all import *
from Crypto.Util.number import *
from secret import flag

def _N2M_(num,wid):
    mat = []
    num = bin(num)[2:].rjust(wid*wid,'0')
    for i in range(wid):
        TMP = []
        for j in range(wid):
            TMP.append(int(num[i*wid + j]))
        mat.append(TMP)
    return mat

def _T_(mat,wid):
    new_mat = []
    for i in range(wid):
        TMP = []
        for j in range(wid):
            TMP.append(int(mat[j][i]))
        new_mat.append(TMP)
    return new_mat

def _GenKeyM_(wid):
    Prime_bits = 256
    primes = [[getPrime(Prime_bits) for i in range(wid)] for j in range(wid)]
    return primes

if __name__ == "__main__":
    wid = 17
    m = bytes_to_long(flag)
    m = _T_(_N2M_(m,wid),wid)

    m = Matrix(ZZ,m)
    key = _GenKeyM_(wid)

    c = m * Matrix(ZZ,key)
    f = open(r'/output','w')

    bigMOD = 2**512
    A = 0x10001
    B = 12138
    KEY = A * Matrix(Zmod(bigMOD),key) + B

    f.write("cipher : \n" + str(c) + '\nKEY :\n' + str(KEY))
    f.close()

```

思路：先对消息进行01加密，成矩阵，然后成17x17的矩阵，然后矩阵乘法，然后给了加密后的K，这里K可以直接计算，然后解密c 

exp.py 

```python
from sage.all import *
from Crypto.Util.number import*

Key = 
K = Matrix(Zmod(2**512),Key)
K = ((K-12138)/0x10001)

NEW_K = Matrix(ZZ,K)

C = 
C = Matrix(ZZ,C)
m = NEW_K.solve_left(C)
M = ''.join(str(i) for i in ((m.T).list()))
print(long_to_bytes(int(M,2)))
```

## 总结

很多都是moe22&21的题，质量挺高的，格部分没怎么写，平台上面也有exp，就这样吧
