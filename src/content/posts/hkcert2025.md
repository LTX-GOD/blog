---
title: HKCERT2025
published: 2025-12-23
pubDate: 2025-12-23
description: HKCERT2025 wp
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

感谢队友吧，`@uncle_cui、@v2tua1、@ClubsS`，周末大战两天，也是每年的必备节目了，最后国际组27，还是没去线下😭

## crypto

### Try E

task.py

```python
from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag

def get_huge_RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    phi = (p - 1) * (q - 1)
    while True:
        d = getPrime(256)
        e = pow(d, -1, phi)
        if e.bit_length() == N.bit_length():
            break
    return N,e

if __name__ == '__main__':
    N, e = get_huge_RSA()
    m = bytes_to_long(flag)
    c = pow(m, e, N)

    print(f'N = {hex(N)}')
    print(f'e = {hex(e)}')
    print(f'c = {hex(c)}')
```

纯签到来的

exp.py

```python
N =
e =
c =

def factor_rsa_wiener(N, e):
    N = Integer(N)
    e = Integer(e)
    cf = (e / N).continued_fraction().convergents()
    for f in cf:
        k = f.numer()
        d = f.denom()
        if k == 0:
            continue
        phi_N = ((e * d) - 1) / k
        b = -(N - phi_N + 1)
        dis = b ^ 2 - 4 * N
        if dis.sign() == 1:
            dis_sqrt = sqrt(dis)
            p = (-b + dis_sqrt) / 2
            q = (-b - dis_sqrt) / 2
            if p.is_integer() and q.is_integer() and (p * q) % N == 0:
                p = p % N
                q = q % N
                if p > q:
                    return (p, q)
                else:
                    return (q, p)
print(factor_rsa_wiener(N,e))

p=
q=N//p

from Crypto.Util.number import *

print(long_to_bytes(pow(c,inverse(e,(p-1)*(q-1)),N)))
#flag{Y0u_kNoW_C0n7lNu3d_Fr4c71on!}
```

### EC Fun

task.py

```python
from Crypto.Cipher import AES
import random

flag = '******'.encode()
p =

have = lambda s,t:
fun = lambda t:
def have_fun(a, b):
    res = g1
    while b:
        if b&1:
            res = have(res,a)
        a = fun(a)
        b >>= 1
    return res

g1 = (,)
g2 = (,)

key = random.randrange(2,1<<54)
y = have_fun(g2, key)

print('y =',y)

cipher = AES.new(str(key).encode()[:16], AES.MODE_ECB)
enc = cipher.encrypt(flag)
print('enc =', enc)

```

一个ECDLP问题，首先我们恢复曲线，后面发现这个和一个古老的题很像，赛宁真是什么题都往上面搬了

恢复参数

```python
res = [have_fun(g2, i) for i in range(100)] + [g1, g2]

# x^3 + Ax^2 + Bx + Cy^2 + Dy + Exy + F = 0
M = []
Y = []
for x, y in res:
    M.append([x**2, x, y**2, y, x * y, 1])
    Y.append(-(x**3))

M = Matrix(Zmod(p), M)
Y = vector(Y)
X = M.solve_right(Y)
```

不是Weierstrass，变形

```python
R = Zmod(p)["x, y"]
(
    x,
    y,
) = R._first_ngens(2)

A, B, C, D, E, F = X
f = x**3 + A * x**2 + B * x + C * y**2 + D * y + E * x * y + F

print(X, f, C)


def mapping(point):
    return (-point[0] * pow(C, -1, p) % p, -point[1] * pow(C, -1, p) % p)

f1 = (
    -1 * x**3
    + A * pow(C, -1, p) * x**2
    - B * pow(C, -2, p) * x
    + y**2
    - D * pow(C, -2, p) * y
    + E * pow(C, -1, p) * x * y
    + F * pow(C, -3, p)
)

C1 = EllipticCurve(f1)
```

现在就是ecdlp问题了，`discrete_log`直接求解的效率非常低，把order分解

```python
order = G2.order()
factors = G2.order().factor()
print(factors)
```

有因子的，直接求解

```python
moduli = []
residues = []

for p, e in factors[:-1]:
    assert e == 1
    x = discrete_log_lambda(
        (Y1 - G1) * (order // p), G2 * (order // p), bounds=(0, p), operation="+"
    )
    residues.append(x)
    moduli.append(p)

key = crt(residues, moduli)

assert key == discrete_log(
    (Y1 - G1) * factors[-1][0], G2 * factors[-1][0], operation="+"
)


enc =
cipher = AES.new(str(key).encode()[:16], AES.MODE_ECB)
flag = cipher.decrypt(enc)
print(flag)
```

### Loss N

task.py

```python
from Crypto.Util.number import *
from gmpy2 import *
from secret import flag

m = bytes_to_long(flag)
p = getPrime(512)
q = next_prime(p)
n = p * q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
c = pow(m, e, n)
print(f"c = {c}")
print(f"d = {d}")
```

已知cd的攻击，其实就是解方程组

exp.py

```python
from Crypto.Util.number import isPrime, long_to_bytes
import gmpy2

c =
d =
e = 65537

A = e * d - 1

for k in range(1, e):
    if A % k != 0:
        continue
    phi_candidate = A // k
    for t in range(2, 2000, 2):
        a = 1
        b = t - 2
        c_val = -t + 1 - phi_candidate
        disc = b*b - 4*a*c_val
        if disc < 0:
            continue
        sqrt_disc = gmpy2.isqrt(disc)
        if sqrt_disc * sqrt_disc != disc:
            continue
        p_candidate = (-b + sqrt_disc) // (2*a)
        if p_candidate <= 0:
            continue
        if isPrime(p_candidate) and isPrime(p_candidate + t) and gmpy2.next_prime(p_candidate) == p_candidate + t:
            p = int(p_candidate)
            q = p + t
            n = p * q
            phi = (p-1)*(q-1)
            if (e * d) % phi == 1:
                print(f"Found p = {p}")
                print(f"q = {q}")
                print(f"n = {n}")
                m = pow(c, d, n)
                flag = long_to_bytes(m)
                print(f"flag = {flag}")
# flag{Y0u_kNow_h0w_7o_f4cTor1z3_phI}
```

### LWECC

task.py

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from random import choice
from hashlib import md5
from secret import flag

p =
E = EllipticCurve(GF(p), [0, 5])

s = [E.random_element() for _ in range(73)]
e = [E.random_element() for _ in "01"]
A = random_matrix(GF(p), 137, 73)
b = [(sum(i*j for i,j in zip(_,s)) + choice(e)).xy() for _ in A]


print("A =", A.list())
print("b =", b)
print("enc =", AES.new(key=md5(str(s).encode()).digest(), nonce=b"LWECC", mode=AES.MODE_CTR).encrypt(flag))
```

首先你要发现，这玩意的阶等于p，那么使用Smart攻击即可转到GF(p)上，然后的你可以发现他和[maple](https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202025/BabyLWE)的一个题很像，也和[鸡块](https://tangcuxiaojikuai.xyz/post/94c7e291.html)的一个题很像，这里两边借鉴

然后我发现maple的脚本直接一把梭了bro，nmd赛宁，怪不得差评这么多

exp.py

```python
A=[]
b=[]
enc =
from lll_cvp import reduce_mod_p
from Crypto.Cipher import AES
from hashlib import md5
def smart(P, Q):
    """
    Smart's attack in "The Discrete Logarithm Problem on Elliptic Curves of
    Trace One": find k such that k * P = Q

    Args:
        P: the P in k * P = Q
        Q: the Q in k * P = Q

    Returns:
        the recovered k
    """

    from sage.all import EllipticCurve, Qp, ZZ, randint, GF

    # references:
    # https://link.springer.com/article/10.1007/s001459900052
    # https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py
    # https://ctftime.org/writeup/29702
    # https://shiftleft.com/mirrors/www.hpl.hp.com/techreports/97/HPL-97-128.pdf
    # https://crypto.stackexchange.com/questions/70454/why-smarts-attack-doesnt-work-on-this-ecdlp

    # order of E(Fp) equals to p
    E = P.curve()
    F = E.base_ring()
    p = F.characteristic()
    assert E.order() == p

    # lift the elliptic curve to Qp with precision = 2
    # add random multiples of p to avoid special case
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])

    # lift P
    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    # lift Q
    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    # multiply by p
    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp

    # compute p-adic elliptic logarithm
    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()
    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)

    # compute k
    k = phi_Q / phi_P
    return ZZ(k)

p =
E = EllipticCurve(GF(p), [0, 5])
assert E.order() == p

gen = E.gen(0)
print(gen)

bs = []
for point in b:
    bs.append(smart(gen, E(point)))
print(bs)

F = GF(p)
m = 137
n = 73
A = matrix(F, m, n, A)
b = vector(F, bs)
one = vector(F, [1] * m)

L = A.T.stack(b).stack(one)
rr = reduce_mod_p(L, p)
assert len(set(rr[0])) == 2, "failed QQ"
*_, u, v = L.solve_left(rr[0])
e = (rr[0] - v * one) / u
print(e, set(e))  # vector e
s = A.solve_right(b - e)
s = [i * gen for i in s]

key = md5(str(s).encode()).digest()
aes = AES.new(key, AES.MODE_CTR, nonce=b"LWECC")
flag = aes.decrypt(enc)
print(flag)
```

### copper

task.py

```python
from Crypto.Util.number import *
from secret import *

with open("message", "r") as f:
    message = f.read().strip().encode()

m = bytes_to_long(flag)
message = bytes_to_long(message)

p = getPrime(1024)
q = getPrime(25)
N = p * q
e = 65537

c = pow(message, e, N)
r1, r2 = getPrime(512), getPrime(512)
k = getPrime(64)

t1 = (k * inverse(m + r1, p)) % p
t2 = (k * inverse(m + r2, p)) % p

leak1 = t1 >> 244
leak2 = t2 >> 244

print(f'{e = }')
print(f'{N = }')
print(f'{c = }')

print(f'{k = }')
print(f'{r1 = }')
print(f'{r2 = }')
print(f'{leak1 = }')
print(f'{leak2 = }')
```

pq直接分解出来，t是高位泄露，这里灵机一动，把方程改写成np的近似同余，然后LLL即可

exp.py

```python
e = 65537
N =

k =
r1 =
r2 =

leak1 =
leak2 =

SHIFT = 244

q = min(p for p, _ in factor(N))
p = N // q

U1 = leak1 << SHIFT
U2 = leak2 << SHIFT

C1 = U1 * r1 - k
C2 = U2 * r2 - k

E_bits = 756
X = Integer(1) << (p.nbits() - E_bits)
M = Integer(1) << 760

B = Matrix(ZZ, [
    [p, 0, 0, 0],
    [0, p, 0, 0],
    [-U1, -U2, X, 0],
    [C1, C2, 0, M]
])

B = B.LLL()

for v in B:
    if abs(v[3]) == M or (v[3] % M == 0 and abs(v[3] // M) == 1):
        m = (-v[2]) // X
        print(m.to_bytes((m.nbits() + 7) // 8, 'big'))
        break
```

### cruel_rsa

task.py

```python
from sage.all import *
from sage.crypto.util import random_blum_prime
from Crypto.Util.number import *
from secret import flag

nbit = 512
gamma = 0.44
delta = 0.51
dm,dl = 0.103, 0.145
cpbit = ceil(nbit * gamma)
kbit  = int(nbit * delta)
msbit = int(nbit * dm)
lsbit = int(nbit * dl)
g = random_blum_prime(2**(cpbit - 1), 2**cpbit-1)
while 1:
    p = q = 0
    while is_prime(p) or len(bin(p)) - 2 != nbit // 2:
        a = randint(int(2 ** (nbit // 2 - 2) // g * gamma), 2 ** (nbit // 2 - 1) // g)
        p = 2 * g * a + 1
    while is_prime(q) or len(bin(q)) - 2 != nbit // 2:
        b = randint(int(2 ** (nbit // 2 - 2) // g * gamma), 2 ** (nbit // 2 - 1) // g)
        q = 2 * g * b + 1
    L = 2 * g * a * b
    if is_prime(L + a + b):
        n = p * q
        break

d = random_prime(2**kbit-1, lbound=2**(kbit - 1))
e = inverse_mod(d, L)
k = (e * d - 1) // L
dm = d // (2 ** (kbit - msbit))
dl = d % (2 ** lsbit)
m = bytes_to_long(flag)
print(dm, dl, e, n)
print(pow(m, e, n))
```

本来以为是重量级，结果是重量级，n可以直接分解的，sb出题人

exp.py

```python
n=8073736467273664280056643912209398524942152147328656910931152412352288220476046078152045937002526657533942284160476452038914249779936821603053211888330755
e=36346110007425305872660997908648011390452485009167380402907988449045651435844811625907
c=8042279705649954745962644909235780183674555369775538455015331686608683922326562829164835918982642084136603628007677118144681339970688028985720674063973679

from Crypto.Util.number import *

p=11606767999414698455890262045272382868998286949
q=561544524741926577700278571
print(long_to_bytes(pow(c,inverse(e,(p-1)*(q-1)),p*q)))
```

### ComCompleXX

task.py

```python
import random

from Crypto.Util.number import *
from secret import flag, key

p, q, e, d = key
n = p * q

assert isPrime(p) and isPrime(q) and p.bit_length() == 512 and q.bit_length() == 512
print('d_len:', d.bit_length())
# d_len: 500

class QN:
    def __init__(self, a, b, c, d, n):
        self.a = a % n
        self.b = b % n
        self.c = c % n
        self.d = d % n
        self.n = n
    def __mul__(self, other):
        if isinstance(other, QN) and self.n == other.n:
            n = self.n
            a1, b1, c1, d1 = self.a, self.b, self.c, self.d
            a2, b2, c2, d2 = other.a, other.b, other.c, other.d
            a = (a1*a2 - b1*b2 - c1*c2 - d1*d2) % n
            b = (a1*b2 + b1*a2 + c1*d2 - d1*c2) % n
            c = (a1*c2 - b1*d2 + c1*a2 + d1*b2) % n
            d = (a1*d2 + b1*c2 - c1*b2 + d1*a2) % n
            return QN(a, b, c, d, n)
        return NotImplemented
    def __pow__(self, exp):
        if exp <= 0:
            return QN(1, 0, 0, 0, self.n)
        result = QN(1, 0, 0, 0, self.n)
        base = self
        while exp > 0:
            if exp & 1:
                result = result * base
            base = base * base
            exp >>= 1
        return result
    def __repr__(self):
        return f"({self.a}, {self.b}, {self.c}, {self.d})"
    def __eq__(self, other):
        return (self.a == other.a and self.b == other.b and
                self.c == other.c and self.d == other.d and self.n == other.n)

if __name__ == "__main__":
    m = QN(bytes_to_long(flag), random.randint(1,n-1), random.randint(1,n-1), random.randint(1,n-1), n)
    c = pow(m, e)
    assert pow(c,d) == m

    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {c}")
```

四元数，可以连分数打

exp.py

```python
from Crypto.Util.number import long_to_bytes

class QN:
    def __init__(self, a, b, c, d, n):
        self.a, self.b, self.c, self.d, self.n = a % n, b % n, c % n, d % n, n

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        n = self.n
        return QN(
            (a1*a2 - b1*b2 - c1*c2 - d1*d2) % n,
            (a1*b2 + b1*a2 + c1*d2 - d1*c2) % n,
            (a1*c2 - b1*d2 + c1*a2 + d1*b2) % n,
            (a1*d2 + b1*c2 - c1*b2 + d1*a2) % n,
            n
        )

    def __pow__(self, exp):
        result, base = QN(1, 0, 0, 0, self.n), self
        while exp > 0:
            if exp & 1:
                result = result * base
            base = base * base
            exp >>= 1
        return result

def cf_terms(num, den):
    terms = []
    while den:
        terms.append(num // den)
        num, den = den, num - (num // den) * den
    return terms

def convergents(terms):
    p0, q0, p1, q1 = 0, 1, 1, 0
    for a in terms:
        p, q = a*p1 + p0, a*q1 + q0
        yield p, q
        p0, q0, p1, q1 = p1, q1, p, q

def wiener_recover_d(e, n, c_qn, prefix=b"flag{"):
    for k, d in convergents(cf_terms(e, n)):
        if d == 0 or k == 0 or (e*d - 1) % k != 0:
            continue
        m = c_qn ** d
        if long_to_bytes(m.a).startswith(prefix):
            return d, m
    return None, None

if __name__ == "__main__":
    n =
    e =
    c = QN(
    )

    d, m = wiener_recover_d(e, n, c)
    if d:
        print(long_to_bytes(m.a))
```

还有个说法，`d<n`，那么`d=pow(e,-1,n)`，也可以出来

### POC

task.py

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


class PaddingOracleClass:
    def __init__(self):
        self.key = os.urandom(16)
        self.auth = os.urandom(16)
        self.nonces = set()

        self.update(nonce=os.urandom(12))

    def update(self, nonce: bytes):
        assert nonce not in self.nonces, "Nonce Reuse Detected"

        self.nonces.add(nonce)
        self.nonce = nonce
        self.cnt = 2

    def register(self, username: bytes) -> tuple[bytes, bytes]:
        assert self.cnt, "Out of Services"
        self.cnt -= 1

        aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        aes.update(self.auth)
        tok, en = aes.encrypt_and_digest(pad(username, 16))
        return tok+en

    def login(self, token: bytes) -> bytes:
        assert self.cnt, "Out of Services"
        self.cnt -= 1

        aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        aes.update(self.auth)
        tok, en = token[:-16], token[-16:]
        username = unpad(aes.decrypt_and_verify(tok, en), 16)
        return username


MENU = '''
========== MENU ==========
cnt = {}
nonce = {}

= [U]pdate
= [R]egister
= [L]ogin
= [Q]uit
==========================
'''

poc = PaddingOracleClass()
while True:
    print(MENU.format(poc.cnt, poc.nonce.hex()))
    try:
        inp = input('>').upper()
        if inp == "Q":
            raise Exception

        elif inp == "U":
            poc.update(
                nonce=bytes.fromhex(input("nonce(hex)>"))
            )

        elif inp == "R":
            username = os.urandom(8)
            token = poc.register(username=username)
            print(f"Register!\n{token.hex()}")
            print(username.hex())

        elif inp == "L":
            token = bytes.fromhex(input("token(hex)>"))
            username = poc.login(token=token)
            print(f"Login!")
            if username == b"admin":
                with open("flag", "r") as f:
                    print(f.read())
                raise Exception
            else:
                print(f"Hello, what can I help you? {username.hex()}")
    except:
        print("Bye")
        break
```

`AES-GCM`的多次调用攻击，ai一把梭

exp.py

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
from pwn import *

def gmult(a, b):
    p = 0
    R = 0xe1000000000000000000000000000000
    for i in range(128):
        if (b >> (127 - i)) & 1:
            p ^= a
        high = a & 1
        a >>= 1
        if high:
            a ^= R
    return p

def gpow(a, b):
    r = 1 << 127
    while b:
        if b & 1:
            r = gmult(r, a)
        a = gmult(a, a)
        b >>= 1
    return r

def ginv(a):
    return gpow(a, (1 << 128) - 2)

def solve():
    io = remote("pwn-f4e2f49344.challenge.xctf.org.cn", 9999, ssl=True)

    def update_nonce(n):
        io.sendlineafter(b'>', b'U')
        io.sendlineafter(b'nonce(hex)>', n.hex().encode())

    def register():
        io.sendlineafter(b'>', b'R')
        io.recvuntil(b'\n')
        t = bytes.fromhex(io.recvline().strip().decode())
        u = bytes.fromhex(io.recvline().strip().decode())
        return t, u

    def login(t):
        io.sendlineafter(b'>', b'L')
        io.sendlineafter(b'token(hex)>', t.hex().encode())

    update_nonce(b'\x01' * 12)
    tok1, _ = register()
    tok2, _ = register()

    c1, t1 = tok1[:-16], tok1[-16:]
    c2, t2 = tok2[:-16], tok2[-16:]

    h2 = gmult(
        bytes_to_long(t1) ^ bytes_to_long(t2),
        ginv(bytes_to_long(c1) ^ bytes_to_long(c2))
    )

    update_nonce(b'\x02' * 12)
    tok3, u3 = register()

    c3, t3 = tok3[:-16], tok3[-16:]
    p3 = pad(u3, 16)

    keystream = bytes_to_long(c3) ^ bytes_to_long(p3)
    target_p = pad(b'admin', 16)
    target_c = long_to_bytes(bytes_to_long(target_p) ^ keystream).rjust(16, b'\x00')

    delta = gmult(bytes_to_long(target_c) ^ bytes_to_long(c3), h2)
    target_t = long_to_bytes(bytes_to_long(t3) ^ delta).rjust(16, b'\x00')

    login(target_c + target_t)
    print(io.recvall(timeout=2).decode(errors='ignore'))

if __name__ == "__main__":
    solve()
```

### Triple Key Cipher（\*）

task.c

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#define BLOCK_SIZE 16

FILE *fp;

void Hash(unsigned char *msg, unsigned len)
{
    unsigned char tmp[32];
    memset(tmp, 0, 32);
    memcpy(tmp, msg, len < 32 ? len : 32);
    unsigned char hash[32];
    SHA256(tmp, 32, hash);
    memcpy(msg, hash, len < 32 ? len : 32);
}

void urandom(unsigned char *buf, int len)
{
    fread(buf, 1, len, fp);
}

void twist(unsigned char *msg) {
    unsigned long long in1 = 0, in2 = 0;
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        in1 <<= 4;
        in2 <<= 4;
        in1 |= msg[i] & 0xf;
        in2 |= msg[i] >> 4;
    }
    unsigned long long out1 = 0, out2 = 0;
    out1 = ((3*in1*in1 + in2) ^ (4*in2*in2)) - 2*in1;
    out2 = ((2*in1+in1) ^ (3*in1*in1 + in2)) * (2*in2) - ((3*in1*in1 + in2)*(3*in1*in1 + in2)*(3*in1*in1 + in2) & (8*in2*in2*in2)) - in2;
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        msg[i] = out1 & 0xf;
        msg[i] |= out2 & 0xf;
        out1 >>= 4;
        out2 >>= 4;
    }
}

void triple_key_cipher(int len, unsigned char *msg, unsigned char *key1, unsigned char *key2, unsigned char* key3)
{
    if(len % BLOCK_SIZE != 0)
        return;
    int i, j, k;
    unsigned char key_expand[BLOCK_SIZE][BLOCK_SIZE];
    unsigned char tmp = 0;
    twist(key1);
    for(i = 0; i < BLOCK_SIZE; i++)
        key_expand[0][i] = key1[i];
    for(i = 0; i < BLOCK_SIZE-1; i++)
    {
        key_expand[i+1][0] = key_expand[i][BLOCK_SIZE-1] * key1[0];
        for(j = 0; j < BLOCK_SIZE-1; j++)
            key_expand[i+1][j+1] = key_expand[i][j] + key_expand[i][BLOCK_SIZE-1] * key1[j+1];
    }
    printf("leak: "); for(int i = 0; i < BLOCK_SIZE; i++) printf("%.2hhx", key_expand[BLOCK_SIZE-1][i]); printf("\n");
    for(int block = 0; block < len / BLOCK_SIZE; block++)
    {
        twist(key3);
        unsigned char enc[BLOCK_SIZE];
        for(i = 0; i < BLOCK_SIZE; i++)
            enc[i] = msg[i+block*BLOCK_SIZE] * key2[0];
        for(i = 1; i < BLOCK_SIZE; i++)
        {
            for(j = 0; j < BLOCK_SIZE-i; j++)
                enc[i+j] = enc[i+j] + key2[i] * msg[j+block*BLOCK_SIZE];
            for(j = BLOCK_SIZE-i; j < BLOCK_SIZE; j++)
                for(k = 0; k < BLOCK_SIZE; k++)
                    enc[k] = enc[k] + key2[i] * msg[j+block*BLOCK_SIZE] * key_expand[i+j-BLOCK_SIZE][k];
        }
        for(i = 0; i < BLOCK_SIZE; i++)
            msg[i+block*BLOCK_SIZE] = enc[i] ^ key3[i];
    }
}

int main()
{
    setvbuf(stdin,NULL, 2, 0);
    setvbuf(stdout,NULL, 2, 0);

    fp = fopen("/dev/urandom", "r");

    int i, j;
    unsigned char key1[BLOCK_SIZE], key2[BLOCK_SIZE], key3[BLOCK_SIZE];
    urandom(key2, BLOCK_SIZE);
    Hash(key2, BLOCK_SIZE);
    for(j = 0; j < 10; j++)
    {
        write(1, "1. Encrypt\n2. Get flag\n3. Quit\nYour choice: ", 44);
        unsigned int opcode;
        read(0, &opcode, 1);
        getchar();
        printf("%hhx\n", opcode);
        switch (opcode)
        {
        case '1':
            write(1, "Message: ", 9);
            unsigned char msg[2*BLOCK_SIZE];
            memset(msg, 0, 2*BLOCK_SIZE);
            read(0, msg, 2*BLOCK_SIZE);
            Hash(msg, 2*BLOCK_SIZE);
            urandom(key1, BLOCK_SIZE); urandom(key3, BLOCK_SIZE);
            triple_key_cipher(2*BLOCK_SIZE, msg, key1, key2, key3);
            printf("enc: "); for(int i = 0; i < 2*BLOCK_SIZE; i++) printf("%.2hhx", msg[i]); printf("\n");
            break;
        case '2':
            write(1, "Key: ", 5);
            unsigned char usr_key[BLOCK_SIZE];
            read(0, usr_key, BLOCK_SIZE);
            if(memcmp(usr_key, key2, BLOCK_SIZE) == 0)
            {
                FILE* file = fopen("flag", "r");
                unsigned char flag[60];
                fread(flag, 1, 60, file);
                fclose(file);
                printf("flag: %s\n", flag);
                return 0;
            }
            else
            {
                write(1, "Wrong!\n", 7);
            }
            break;
        case '3':
            return 0;
        default:
            break;
        }
    }
    fclose(fp);
    return 0;
}
```

交互题，加密返回`leak`和`ciphertext`，拿flag需要`key2`.

key1用来生成16x16的展开矩阵
key2是静态密钥，作为信息乘法的自定义矩阵向量
key2用来xor

关键点在于这个函数

```c
void twist(unsigned char *msg) {
    unsigned long long in1 = 0, in2 = 0;
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        in1 <<= 4;
        in2 <<= 4;
        in1 |= msg[i] & 0xf;
        in2 |= msg[i] >> 4;
    }
    unsigned long long out1 = 0, out2 = 0;
    out1 = ((3*in1*in1 + in2) ^ (4*in2*in2)) - 2*in1;
    out2 = ((2*in1+in1) ^ (3*in1*in1 + in2)) * (2*in2) - ((3*in1*in1 + in2)*(3*in1*in1 + in2)*(3*in1*in1 + in2) & (8*in2*in2*in2)) - in2;
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        msg[i] = out1 & 0xf;
        msg[i] |= out2 & 0xf;
        out1 >>= 4;
        out2 >>= 4;
    }
}
```

看第二个for循环里面的内容，`msg[i] |= out2 & 0xf;`没有`<<4`，所以现在两个半字节都被通过OR运算合并到了低4位中。

那么就会导致`MSG[i]`一直处于`[0,15]`中，并且`4~7`位总是0。

key1恢复的方法很简单，z3直接求解就行

看加密

$$
C = (M \cdot K2) \oplus K3
$$

M是key1那边搞出来的，k3的高4位为0，那么xor的影响是有限的，那么

$$
C \& 0xF0 \approx (M \cdot K2) \& 0xF0
$$

我们可以将其改写为对每一个字节j的线性不等式

$$
(M \cdot K2)_j \pmod{256} \in [C_j \& 0xF0, (C_j \& 0xF0) + 15]
$$

这个就是`HNP`了对吧。

exp.py

```python
import binascii
import hashlib

from z3 import *

from pwn import *

BLOCK_SIZE = 16
r = remote("pwn-442eac5d73.challenge.xctf.org.cn", 9999, ssl=True)

def get_trace():
    r.recvuntil(b"Your choice:")
    r.sendline(b"1")
    payload = b"A" * 32
    r.recvuntil(b"Message:")
    r.send(payload)
    r.recvuntil(b"leak: ")
    leak = binascii.unhexlify(r.recvline().strip().decode())
    r.recvuntil(b"enc: ")
    enc = binascii.unhexlify(r.recvline().strip().decode())
    msg = hashlib.sha256(payload).digest()
    return msg, leak, enc

print("[*] Collecting traces...")
traces = [get_trace() for _ in range(2)]
all_matrices = []
all_targets = []

for msg, leak, enc in traces:
    s = Solver()
    k1 = [BitVec(f"k1_{i}", 8) for i in range(BLOCK_SIZE)]
    row = k1
    for _ in range(BLOCK_SIZE - 1):
        nxt = [BitVecVal(0, 8)] * BLOCK_SIZE
        f = row[BLOCK_SIZE-1]
        nxt[0] = f * k1[0]
        for j in range(BLOCK_SIZE - 1):
            nxt[j+1] = row[j] + f * k1[j+1]
        row = nxt

    for i in range(BLOCK_SIZE):
        s.add(row[i] == leak[i])
        s.add(ULE(k1[i], 15))

    s.check()
    m_z3 = s.model()
    k1_val = [m_z3[k1[i]].as_long() for i in range(BLOCK_SIZE)]

    key_expand = [k1_val]
    curr_row = list(k1_val)
    for _ in range(BLOCK_SIZE - 1):
        nr = [0]*BLOCK_SIZE
        f = curr_row[BLOCK_SIZE-1]
        nr[0] = (f * k1_val[0]) & 0xFF
        for j in range(BLOCK_SIZE - 1):
            nr[j+1] = (curr_row[j] + f * k1_val[j+1]) & 0xFF
        key_expand.append(nr)
        curr_row = nr

    for b in range(2):
        msg_blk, enc_blk = msg[b*16:b*16+16], enc[b*16:b*16+16]
        M = [[0]*16 for _ in range(16)]
        for col in range(16):
            e = [0]*16
            if col == 0: e = list(msg_blk)
            else:
                for j in range(16 - col): e[col+j] = (e[col+j] + msg_blk[j]) & 0xFF
                for j in range(16 - col, 16):
                    row_red = key_expand[col + j - 16]
                    for k in range(16): e[k] = (e[k] + msg_blk[j] * row_red[k]) & 0xFF
            for row_idx in range(16): M[row_idx][col] = e[row_idx]
        all_matrices.extend(M)
        for val in enc_blk: all_targets.append((val & 0xF0) + 7)

n, m, mod, W = 16, len(all_matrices), 256, 128
dim = n + m + 1
L = Matrix(ZZ, dim, dim)
for i in range(n): L[i, i] = 1
for j in range(m):
    for i in range(n): L[i, n+j] = all_matrices[j][i] * W
    L[n+j, n+j] = mod * W
    L[dim-1, n+j] = -all_targets[j] * W
L[dim-1, dim-1] = 1

L_red = L.LLL()
for row in L_red:
    if abs(row[dim-1]) == 1:
        sign = 1 if row[dim-1] == 1 else -1
        key2_val = bytes([(row[i]*sign) % 256 for i in range(n)])
        break

print(f"[+] Key2: {key2_val.hex()}")
r.recvuntil(b"Your choice:")
r.sendline(b"2")
r.recvuntil(b"Key: ")
r.send(key2_val)
print(r.recvall().decode())
```

## 总结

感觉没有去年的题目好玩了，今年的题目过于ctf了，但是CTF根本不是这样的。。。

比赛安排、整体质量都不如去年友好，不知道为什么会有这样的安排，好像也是被骂的最多的一次，希望越来越好吧。。

也许以后能进一次线下呢对把。
