---
title: 巅峰极客2024_crypto
published: 2024-12-12
pinned: false
description: 巅峰极客2024，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2024-12-12
pubDate: 2024-12-12
---


<h2>
前言
</h2>
应该是这个暑假里面(目前)打的最难的一场了，相比于das，他就上一个密码题啊我靠，八个小时，上了三波题，就开局一个密码，还是没写过的ECDSA加密，写不出来就很尴尬也很痛苦
<br>

<h2>题目</h2>
<h3>task</h3>

```
from ecdsa.ecdsa import *
from Crypto.Util.number import *
import hashlib
import gmpy2

def inverse_mod(a, m):
    if a == 0:
        return 0
    return gmpy2.powmod(a, -1, m)

def bit_length(x):
    return x.bit_length()

def get_malicious_key():
    a = 751818   
    b = 1155982
    w = 908970521
    X = 20391992
    return a, b, w, X

class RSZeroError(RuntimeError):
    pass


class InvalidPointError(RuntimeError):
    pass


class Signature(object):
    """ECDSA signature."""

    def __init__(self, r, s):
        self.r = r
        self.s = s


class Public_key(object):
    """Public key for ECDSA."""

    def __init__(self, generator, point, verify=True):

        self.curve = generator.curve()
        self.generator = generator
        self.point = point
        n = generator.order()
        p = self.curve.p()
        if not (0 <= point.x() < p) or not (0 <= point.y() < p):
            raise InvalidPointError(
                "The public point has x or y out of range."
            )
        if verify and not self.curve.contains_point(point.x(), point.y()):
            raise InvalidPointError("Point does not lay on the curve")
        if not n:
            raise InvalidPointError("Generator point must have order.")

        if (
            verify
            and self.curve.cofactor() != 1
            and not n * point == ellipticcurve.INFINITY
        ):
            raise InvalidPointError("Generator point order is bad.")


class Private_key(object):
    """Private key for ECDSA."""

    def __init__(self, public_key, secret_multiplier):

        self.public_key = public_key
        self.secret_multiplier = secret_multiplier

    def sign(self, hash, random_k):

        G = self.public_key.generator
        n = G.order()# 获取该椭圆模数
        
        k = random_k % n

        p1 = k * G
        r = p1.x() % n
        if r == 0:
            raise RSZeroError("amazingly unlucky random number r")
        s = (
            inverse_mod(k, n)
            * (hash + (self.secret_multiplier * r) % n)
        ) % n
        if s == 0:
            raise RSZeroError("amazingly unlucky random number s")
        return Signature(r, s)

    def malicious_sign(self,hash, random_k, a, b, w, X):
        # t = random.randint(0,1)
        t = 1
        G = self.public_key.generator
        Y = X * G
        n = G.order()
        k1 = random_k
        z = (k1 - w * t) * G + (-a * k1 - b) * Y
        zx = z.x() % n
        k2 = int(hashlib.sha1(str(zx).encode()).hexdigest(), 16)
        #print(f'k2 = {k2}')
        p1 = k2 * G
        r = p1.x() % n
        if r == 0:
            raise RSZeroError("amazingly unlucky random number r")
        s = (
                    inverse_mod(k2, n)
                    * (hash + (self.secret_multiplier * r) % n)
            ) % n
        if s == 0:
            raise RSZeroError("amazingly unlucky random number s")
        return (Signature(r, s),k2)

if __name__ == '__main__':
    a,b,w,X = get_malicious_key()
   
    message1 = b'It sounds as though you were lamenting,'
    message2 = b'a butterfly cooing like a dove.'
    hash_message1 = int(hashlib.sha1(message1).hexdigest(), 16)
    hash_message2 = int(hashlib.sha1(message2).hexdigest(), 16)
    private = getRandomNBitInteger(50)
    rand = getRandomNBitInteger(49)
    public_key = Public_key(generator_192, generator_192 * private)
    private_key = Private_key(public_key, private)
    sig = private_key.sign(hash_message1, rand)
    malicious_sig,k2 = private_key.malicious_sign(hash_message2, rand, a,b,w,X)
    
    print(a,b,w,X)
    print(sig.r)
    print(malicious_sig.r)

    '''
    751818 1155982 908970521 20391992
    sig.r=6052579169727414254054653383715281797417510994285530927615
    malicious_sig.r=3839784391338849056467977882403235863760503590134852141664
    '''
    
    # flag为flag{uuid}格式
    flag = b''
    m = bytes_to_long(flag)
    p = k2
    for i in range(99):
        p = gmpy2.next_prime(p)
    q = gmpy2.next_prime(p)
    e = 65537
    c = pow(m,e,p*q)
    print(c)
    # 1294716523385880392710224476578009870292343123062352402869702505110652244504101007338338248714943
```
写题的时候有一些地方被我改了一点点，应该可以看出来（）

<h3>思路</h3>
刚拿到这个题目的时候第一想法是恢复k1再去恢复k2，第二遍读代码的时候看见 public_key = Public_key(generator_192, generator_192 * private),这就确定了这个曲线是curve_192，我又知道r，那我就可以直接去求出p，求p这里方法比较多，在网上找了个二次剩余的方法，求出p。

$$z = (k1 - w * t) * G + (-a * k1 - b) * Y $$
$$化简成$$

$$z=p1+(-w)*G+(-a)*X*p1+(-b)*X*G$$

那么这个题就出来了

exp
```
import hashlib
import gmpy2
from Crypto.Util.number import *

r1=6052579169727414254054653383715281797417510994285530927615

#curve_192
p=6277101735386680763835789423207666416083908700390324961279
a=-3
b=2455155546008943817740293915197451784769108058161191238065

def convert_to_base(n, b):
    if n < 2:
        return [n]

    temp = n
    ans = []

    while temp != 0:
        ans = [temp % b] + ans
        temp //= b

    return ans


def cipolla(n, p):
    n %= p

    if n == 0 or n == 1:
        return [n, (p - n) % p]

    phi = p - 1

    if pow(n, phi // 2, p) != 1:
        return []

    if p % 4 == 3:
        ans = int(pow(n, (p + 1) // 4, p))
        return [ans, (p - ans) % p]

    aa = 0
    for i in range(1, p):
        temp = pow(((i * i - n) % p), phi // 2, p)

        if temp == phi:
            aa = i
            break

    exponent = convert_to_base((p + 1) // 2, 2)

    def cipolla_mult(ab, cd, w, p):
        a, b = ab
        c, d = cd
        return (a * c + b * d * w) % p, (a * d + b * c) % p

    x1 = (aa, 1)
    x2 = cipolla_mult(x1, x1, aa * aa - n, p)

    for i in range(1, len(exponent)):
        if exponent[i] == 0:
            x2 = cipolla_mult(x2, x1, aa * aa - n, p)
            x1 = cipolla_mult(x1, x1, aa * aa - n, p)
        else:
            x1 = cipolla_mult(x1, x2, aa * aa - n, p)
            x2 = cipolla_mult(x2, x2, aa * aa - n, p)
    return [x1[0], (p - x1[0]) % p]

y12=(r1**3+a*r1+b)%p
print(cipolla(y12, p))

# sage

E = EllipticCurve(GF(p),[a,b])
G = E(602046282375688656758213480587526111916698976636884684818,174050332293622031404857552280219410364023488927386650641) 
p1 = E(6052579169727414254054653383715281797417510994285530927615, 5871535981004787479780408408652175440419840647034147933664) 
a,b,w,X=751818 ,1155982, 908970521, 20391992

z=p1+(-w)*G+(-a)*X*p1+(-b)*X*G
#z = (k1 - w * t) * G + (-a * k1 - b) * Y
print(z)

zx=2879837810202640866238433125146194557887945787271835955457
k2 = int(hashlib.sha1(str(zx).encode()).hexdigest(), 16)
print(k2)

p = k2
for i in range(99):
    p = gmpy2.next_prime(p)
q = gmpy2.next_prime(p)
print(p,q)


#

p=1370020847323284147745373471297398364094203631317
q=1370020847323284147745373471297398364094203631323

phi=(p-1)*(q-1)
d=inverse(65537, phi)
n=p*q
c=1294716523385880392710224476578009870292343123062352402869702505110652244504101007338338248714943

for i in range(2**16):
    if b'flag' in long_to_bytes(pow(c,d, p*q)+n*i):
        print(long_to_bytes(pow(c,d, p*q)+n*i))

```
这个方法绕过了k1直接去求k2
<br>
还有一个求k1的方法，貌似更简单，用大步小步算法去求解
exp
```
from ecdsa.ecdsa import *
import libnum 
import re
import gmpy2
from Crypto.Util.number import *

def BSGS(G, P, x1, x2):
    m = ceil(sqrt(x2 - x1))
    baby_steps = {}
    current_step = G
    for j in trange(m):
        k_j = x1 + j
        baby_steps[current_step] = k_j
        current_step += G

    mP = m * G
    S = P
    for i in trange(m):
        if S in baby_steps:
            return baby_steps[S] + i * m
        S -= mP 

    return None

# BSGS(G, P, round(2**48.9), round(2**49))

_p = 6277101735386680763835789423207666416083908700390324961279
def remove_whitespace(text):
    """Removes all whitespace from passed in string"""
    return re.sub(r"\s+", "", text, flags=re.UNICODE)
_b = int(
    remove_whitespace(
        """
    64210519 E59C80E7 0FA7E9AB 72243049 FEB8DEEC C146B9B1"""
    ),
    16,
)
E = EllipticCurve(GF(_p),[-3, _b])

G = generator_192

r1 = 6052579169727414254054653383715281797417510994285530927615
a = -3
Py = r1^3 + a * r1 + _b
Py = sqrt(Mod(Py, _p))
P = E(r1,Py)

# k1 = optimized_bsgs_in_range(G,P,)

c = 1294716523385880392710224476578009870292343123062352402869702505110652244504101007338338248714943
a = 751818
b = 1155982
w = 908970521
X = 20391992

k1 = 432179965122662

t = 1
Y = X * G
n = G.order()
z = (k1 - w * t) * G + (-a * k1 - b) * Y
zx = z.x() % n
k2 = int(hashlib.sha1(str(zx).encode()).hexdigest(), 16)
p = k2
print(P.x())
print(P.y())
print(type(P))
for i in range(99):
    p = gmpy2.next_prime(p)
q = gmpy2.next_prime(p)
e = 65537
d = libnum.invmod(e,(p-1)*(q-1))
m = pow(c,d,p*q)
for i in range(2 ** 16):
    m += p*q
    flag = long_to_bytes(int(m))
    if b"flag" in flag:
        print(i)
        print(flag)
        break
```

<h2>总结</h2>
还是太菜了，还得练，害，有些东西没有接触过，就导致看代码如懂，写题很烦躁，继续努力加油吧！