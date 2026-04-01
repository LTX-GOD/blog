---
title: polarisctf2026
published: 2026-03-30
pubDate: 2026-03-30
description: polarisctf2026 zsm crypto wp
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

比赛的时候一看全是ai冲榜，xd炸钢了，就写了写crypto，apk那个题是后面出来的，可惜了

## 题目

### ez_login

app.py

```python
from flask import Flask, request, make_response, render_template, redirect, url_for, abort
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
KEY = os.getenv("SECRET_KEY", os.urandom(16))
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
FLAG = os.getenv("FLAG", "XMCTF{xxxxxx}")

# 初始数据，禁止注册 admin
USERS = {"admin": ADMIN_PASS}

def get_session_data(token_hex):
    if not token_hex: return None
    data = bytes.fromhex(token_hex)
    iv, ct = data[:16], data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ct)
    print(decrypted)
    return unpad(decrypted, 16).decode(errors='ignore')

def create_session(username):
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    msg = f"user={username}".encode()
    ct = cipher.encrypt(pad(msg, 16))
    return (iv + ct).hex()

@app.route('/')
def index():
    token = request.cookies.get('session')
    if not token:
        return redirect(url_for('login_page'))

    try:
        msg = get_session_data(token)
        if not msg or not msg.startswith("user="):
            return redirect(url_for('login_page'))

        username = msg[5:]
    except:
        abort(500, description="Invalid Session")

    return render_template('index.html', username=username, flag=FLAG if username == "admin" else None)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')

    user = request.form.get('username')
    pw = request.form.get('password')

    if USERS.get(user) == pw:
        resp = make_response(redirect(url_for('index')))
        resp.set_cookie('session', create_session(user))
        return resp
    return "Invalid username or password", 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

```

正常人第一眼看上去应该是打`CBC padding oracle`，其实弱密码登录就行`admin\admin123`,正常打也不难，脚本如下(ai)

```python
import sys

import requests

URL = "http://nc1.ctfplus.cn:36477"


def check_padding(iv, ct):
    cookie = (iv + ct).hex()
    try:
        r = requests.get(URL + "/", cookies={"session": cookie}, allow_redirects=False)
        return r.status_code != 500
    except requests.exceptions.RequestException:
        return False


ct = bytearray([0] * 16)
I = bytearray([0] * 16)


for pad_val in range(1, 17):
    idx = 16 - pad_val
    iv = bytearray([0] * 16)

    for i in range(idx + 1, 16):
        iv[i] = I[i] ^ pad_val

    found = False
    for guess in range(256):
        iv[idx] = guess
        if check_padding(iv, ct):
            if pad_val == 1:
                iv[idx - 1] ^= 0xFF
                if not check_padding(iv, ct):
                    iv[idx - 1] ^= 0xFF  # 还原
                    continue
                iv[idx - 1] ^= 0xFF  # 还原

            I[idx] = guess ^ pad_val
            print(f"[+] 发现第 {idx} 字节: {hex(I[idx])}")
            found = True
            break

    if not found:
        print("[-] 爆破失败，请检查网络或 URL。")
        sys.exit(1)

print("[*] 中间状态 (I0) 爆破完成:", I.hex())

target_pt = b"user=admin" + bytes([6] * 6)

# 逆向计算出我们需要发送的伪造 IV
final_iv = bytearray(16)
for i in range(16):
    final_iv[i] = I[i] ^ target_pt[i]

final_cookie = (final_iv + ct).hex()
print("[+] 成功伪造 Admin Session Token:", final_cookie)

# 用伪造的 Cookie 获取 Flag
print("[*] 正在请求获取 Flag...")
r = requests.get(URL + "/", cookies={"session": final_cookie})

if "XMCTF{" in r.text or "flag{" in r.text:
    print("\n[🎉] 获取成功！页面内容：")
    print("-" * 50)
    # 提取并打印包含 flag 的那几行HTML
    for line in r.text.split("\n"):
        if "flag" in line.lower() or "xmctf" in line.lower():
            print(line.strip())
    print("-" * 50)
else:
    print("[-] 未找到 Flag，请检查返回的页面内容：")
    print(r.text)
```

### ECC

task.py

```python
from Crypto.Util.number import *
from secrets import flag

p =
a = 0
b =
c =
d =
e =


def add(P1, P2):
    if P1 is None:
        return P2

    x1, y1 = P1
    x2, y2 = P2

    l = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l**2 + a * l - b - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1 - a * x3 - c) % p
    return (x3, y3)


def double(P):
    if P is None:
        return None

    x, y = P

    denom = (2 * y + a * x + c) % p
    num = (3 * x**2 + 2 * b * x + d - a * y) % p
    l = (num * pow(denom, -1, p)) % p
    x3 = (l**2 + a * l - b - 2 * x) % p
    y3 = (l * (x - x3) - y - a * x3 - c) % p
    return (x3, y3)


def mul(k, P):
    Q = None
    while k:
        if k & 1:
            Q = add(Q, P)
        P = double(P)
        k >>= 1
    return Q


m = bytes_to_long(flag)
G = (, )
P = mul(m, G)
print(P)
```

看看曲线是`广义 Weierstrass 形式`，正常打配方转换成奇异椭圆曲线

solve.py

```python
from Crypto.Util.number import *

p =
a = 0
b =
c =

G = (
    ,
    ,
)
P = (
    ,
    ,
)

yc = (-c * pow(2, -1, p)) % p
xc = (-b * pow(3, -1, p)) % p


def phi(Pt):
    x, y = Pt
    return (x - xc) * pow(y - yc, -1, p) % p


u = phi(P)
v = phi(G)

m = (u * pow(v, -1, p)) % p
print(long_to_bytes(m))

```

### truck

chal.py

```python
from hashlib import md5
from secret import flag

_H = lambda m: md5(m).digest()

S = set()

for _ in range(10):
    A, B, C = bytes.fromhex(input('A > ')), bytes.fromhex(input('B > ')), bytes.fromhex(input('C > '))
    ha, hb, hc = _H(A), _H(B), _H(C)
    assert ha == hb == hc

    D, E, F = bytes.fromhex(input('D > ')), bytes.fromhex(input('E > ')), bytes.fromhex(input('F > '))
    hd, he, hf = _H(ha + D), _H(hb + E), _H(hc + F)
    assert hd == he == hf

    G, H, I = bytes.fromhex(input('G > ')), bytes.fromhex(input('H > ')), bytes.fromhex(input('I > '))
    assert _H(hd + G) == _H(he + H) == _H(hf + I)

    cur = (A, B, C, D, E, F, G, H, I)
    assert len(set(cur)) == 9
    assert not any(x in S for x in cur)
    S.update(cur)

print(f'good: {flag}')
```

碰撞的题目，好像现在都喜欢出这个？？？`fastcoll`本地撞好传上去就行，注意是三层校验，多爆一下得

exp.py

```python
import hashlib
import os
import subprocess

from pwn import *

FASTCOLL = "/Users/zsm/CTF/tool/hashclash/bin/md5_fastcoll"


def get_fastcoll(prefix: bytes) -> tuple[bytes, bytes]:
    with open("prefix.bin", "wb") as f:
        f.write(prefix)

    subprocess.run(
        [FASTCOLL, "-p", "prefix.bin", "-o", "out1.bin", "out2.bin"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    with open("out1.bin", "rb") as f:
        out1 = f.read()
    with open("out2.bin", "rb") as f:
        out2 = f.read()

    m1 = out1[len(prefix) :]
    m2 = out2[len(prefix) :]
    return m1, m2


def generate_round():

    prefix_A = os.urandom(64)
    m1, m2 = get_fastcoll(prefix_A)
    m3, m4 = get_fastcoll(prefix_A + m1)

    A = prefix_A + m1 + m3
    B = prefix_A + m1 + m4
    C = prefix_A + m2 + m3
    ha = hashlib.md5(A).digest()

    pad_D = os.urandom(48)
    prefix_D = ha + pad_D
    m5, m6 = get_fastcoll(prefix_D)
    m7, m8 = get_fastcoll(prefix_D + m5)

    D = pad_D + m5 + m7
    E = pad_D + m5 + m8
    F = pad_D + m6 + m7
    hd = hashlib.md5(ha + D).digest()
    pad_G = os.urandom(48)
    prefix_G = hd + pad_G
    m9, m10 = get_fastcoll(prefix_G)
    m11, m12 = get_fastcoll(prefix_G + m9)

    G = pad_G + m9 + m11
    H = pad_G + m9 + m12
    I = pad_G + m10 + m11

    return (A, B, C, D, E, F, G, H, I)


def main():
    rounds_data = []
    for i in range(10):
        print(f"[*] 正在计算第 {i + 1}/10 轮...")
        rounds_data.append(generate_round())

    for f in ["prefix.bin", "out1.bin", "out2.bin"]:
        if os.path.exists(f):
            os.remove(f)

    p = remote("nc1.ctfplus.cn", 36943)

    for i, r_data in enumerate(rounds_data):
        A, B, C, D, E, F, G, H, I = r_data
        p.sendlineafter(b"A > ", A.hex().encode())
        p.sendlineafter(b"B > ", B.hex().encode())
        p.sendlineafter(b"C > ", C.hex().encode())
        p.sendlineafter(b"D > ", D.hex().encode())
        p.sendlineafter(b"E > ", E.hex().encode())
        p.sendlineafter(b"F > ", F.hex().encode())
        p.sendlineafter(b"G > ", G.hex().encode())
        p.sendlineafter(b"H > ", H.hex().encode())
        p.sendlineafter(b"I > ", I.hex().encode())

    p.interactive()


if __name__ == "__main__":
    main()
```

### 神秘学

task.py

```python
import random

import sympy
from Crypto.Util.number import *
from secret import c, flag


def get_poly(k):
    x, a, b = sympy.symbols("x a b")

    poly = x**3 - a * x**2 + b * x - c - k * n
    deriv1 = sympy.diff(poly, x)

    a1 = random.randint(2**119, 2**120)
    b1 = random.randint(2**119, 2**120)
    x1 = random.randint(2**510, 2**511)

    deriv1_num = deriv1.subs({x: x1, a: a1, b: b1})
    return x1, deriv1_num


def RSA():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    k = getPrime(8)
    m = bytes_to_long(flag)
    e = inverse(c, (p - 1) * (q - 1))
    cipher = pow(m, e, n)
    return n, k, cipher


if __name__ == "__main__":
    n, k, cipher = RSA()
    x1, deriv1_num = get_poly(k)
    print("n =", n)
    print("x1 =", x1)
    print("cipher =", cipher)
    print("deriv1_num =", deriv1_num)
```

这个题就很神秘你知道吧，我第一开始以为是要打二元copper，因为ab是可以出来的，我误以为两个n不一样，然后一直调参数出不来，然后爆破一下出来了，md

solve.py

```python
import sympy
from Crypto.Util.number import *

n = 63407394080105297388278430339692150920405158535377818019441803333853224630295862056336407010055412087494487003367799443217769754070745006473326062662322624498633283896600769211094059989665020951007831936771352988585565884180663310304029530702695576386164726400928158921458173971287469220518032325956366276127
x1 = 3481408902400626584294863390184557833125008467348169645656825368985677578418186933223051810792813745190000132321911937970968840332589150965113386330575858
deriv1_num = 36360623837143006554133449776905822223850034204333042340303731846698251185379183585401025894584873826284649058526470710038176516677326058549625930550928515944115160614909195746688504416967586844354012895944251800672195553936202084073217078119494546421088598245791873936703883718926122761577400400368341859847
cipher = 17359360992646515022812225990358117265652240629363564764503325024700251560440679272576574598620940996876220276588413345495658258508097150181947839726337961689195064024953824539654084620226127592330054674517861032601638881355220119605821814412919221685287567648072575917662044603845424779210032794782725398473


a1 = (3 * x1 * x1 - deriv1_num) // (2 * x1) + 1
b1 = deriv1_num - 3 * x1 * x1 + 2 * a1 * x1


kk = list(sympy.primerange(2**7, 2**8))


for k in kk:
    c = x1**3 - a1 * x1 * x1 + b1 * x1 - k * n

    m = pow(cipher, c, n)
    ff = long_to_bytes(m)
    if b"xmctf" in ff:
        print(ff)
        break
```

### RSA_LCG

task.py

```python
from Crypto.Util.number import getPrime, bytes_to_long
import random
import os
import signal

FLAG = os.environ.get("FLAG", "XMCTF{fake_flag}")
secret = os.urandom(64)

e = 263
bit_length = 1024


def get_rsa_params():
    p = getPrime(bit_length)
    q = getPrime(bit_length)
    N = p * q
    return N


class RSA_LCG:
    def __init__(self, seed, a, b, N):
        self.seed = seed
        self.a = a
        self.b = b
        self.N = N
        self.e = e

    def leak_params(self):

        diff = (self.b - self.a) % self.N
        leak_diff_e = pow(diff, self.e, self.N)

        return  self.a, leak_diff_e


    def next(self):

        self.seed = (self.a * self.seed + self.b) % self.N

        return pow(self.seed, self.e, self.N)


def challenge():

    N = get_rsa_params()

    seed = bytes_to_long(secret)
    assert seed < N

    a = random.getrandbits(bit_length)
    b = random.getrandbits(bit_length)

    rsa_lcg = RSA_LCG(seed, a, b, N)

    print(f"N = {N}")
    print(f"e = {e}")
    print("-" * 30)


    leak = rsa_lcg.leak_params()
    print(f"[+] leak: {leak}")


    out1 = rsa_lcg.next()
    print(f"[+] Output 1: {out1}")

    out2 = rsa_lcg.next()
    print(f"[+] Output 2: {out2}")


if __name__ == "__main__":
    challenge()
    signal.alarm(4)
    guess_hex = input("secret (hex): ").strip()
    guess = bytes.fromhex(guess_hex)
    if guess == secret:
        print(f"Good! Here is your flag: {FLAG}")
```

第一眼看上去其实可以看出来富兰克林攻击，但是会炸时间还有参数，这里思路如下

```
d = b - a mod N
b = d + a
x1 = a * secret + b = d + a * (secret + 1)
x2 = a * x1 + b = a * x1 + d + a

有三个关系
d^e mod N = leak
x1^e mod N = out1
(a*x1 + d + a)^e mod N = out2

多项式启动
f1(x) = x^e - out1
f2(x,d) = (a*x + d + a)^e - out2
f3(d) = d^e - leak

为了消去d，我们要对 f2(x,d) 和 f3(d) 关于变量 d 做 resultant

再和 x1^e = out1 联立
f1(x1) = x1^e - out1 = 0 mod N

那么gcd可以恢复了x1
```

速度优化什么的让ai来干吧，我是不会了xd

solve.py

```python
import ast
import os
import pickle
import socket
from math import ceil

import gmpy2

try:
    import flint
except ImportError:
    flint = None


HOST = "nc1.ctfplus.cn"
PORT = 41668
E = 263
CACHE_FILE = os.path.join(os.path.dirname(__file__), "step_cache_263.pkl")


def batch_invert(values, modulus):
    prefix = [gmpy2.mpz(1)] * len(values)
    acc = gmpy2.mpz(1)
    for i, value in enumerate(values):
        prefix[i] = acc
        acc = gmpy2.f_mod(acc * value, modulus)
    inv_acc = gmpy2.invert(acc, modulus)
    out = [0] * len(values)
    for i in range(len(values) - 1, -1, -1):
        out[i] = gmpy2.f_mod(inv_acc * prefix[i], modulus)
        inv_acc = gmpy2.f_mod(inv_acc * values[i], modulus)
    return out


def build_step_products():
    steps = []
    offsets = [0]
    for n in range(1, E + 1):
        for k in range(n):
            base1 = E * (n - k)
            base2 = E * k
            num = 1
            den = 1
            for t in range(1, E + 1):
                num *= base1 - t + 1
                den *= base2 + t
            steps.append((num, den))
        offsets.append(len(steps))
    return {"steps": steps, "offsets": offsets}


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "rb") as fh:
            return pickle.load(fh)
    cache = build_step_products()
    with open(CACHE_FILE, "wb") as fh:
        pickle.dump(cache, fh, protocol=pickle.HIGHEST_PROTOCOL)
    return cache


STEP_CACHE = load_cache()


def build_step_multipliers(modulus):
    modulus = gmpy2.mpz(modulus)
    denoms = [gmpy2.mpz(den) % modulus for _, den in STEP_CACHE["steps"]]
    den_inv = batch_invert(denoms, modulus)
    return [
        gmpy2.f_mod(gmpy2.mpz(num) * inv, modulus)
        for (num, _), inv in zip(STEP_CACHE["steps"], den_inv)
    ]


def build_power_sums(c2, leak, modulus, step_mult):
    modulus = gmpy2.mpz(modulus)
    c2 = gmpy2.mpz(c2)
    leak = gmpy2.mpz(leak)
    offsets = STEP_CACHE["offsets"]
    neg_leak = gmpy2.f_mod(-leak, modulus)
    inv_neg_leak = gmpy2.invert(neg_leak, modulus)
    sums = [0] * (E + 1)
    for n in range(1, E + 1):
        choose = gmpy2.mpz(1)
        c_pow = gmpy2.mpz(1)
        l_pow = gmpy2.powmod(neg_leak, n, modulus)
        total = gmpy2.mpz(0)
        base = offsets[n - 1]
        for k in range(n + 1):
            total = gmpy2.f_mod(total + choose * c_pow * l_pow, modulus)
            if k == n:
                break
            choose = gmpy2.f_mod(choose * step_mult[base + k], modulus)
            c_pow = gmpy2.f_mod(c_pow * c2, modulus)
            l_pow = gmpy2.f_mod(l_pow * inv_neg_leak, modulus)
        sums[n] = gmpy2.f_mod(E * total, modulus)
    return sums


def build_resultant_coeffs(c2, leak, modulus):
    modulus = gmpy2.mpz(modulus)
    step_mult = build_step_multipliers(modulus)
    sums = build_power_sums(c2, leak, modulus, step_mult)

    elem = [0] * (E + 1)
    elem[0] = gmpy2.mpz(1)
    for k in range(1, E + 1):
        acc = gmpy2.mpz(0)
        sign = 1
        for i in range(1, k + 1):
            acc += sign * elem[k - i] * sums[i]
            sign = -sign
        elem[k] = gmpy2.f_mod(acc * gmpy2.invert(k, modulus), modulus)

    coeffs = [0] * (E + 1)
    for r in range(E + 1):
        coeffs[E - r] = int(gmpy2.f_mod(((-1) ** r) * elem[r], modulus))
    return coeffs


def mul_mod_xe_minus_c(poly_a, poly_b, c, modulus):
    size = len(poly_a)
    out = [0] * size
    for i, ai in enumerate(poly_a):
        if not ai:
            continue
        for j, bj in enumerate(poly_b):
            if not bj:
                continue
            k = i + j
            term = ai * bj % modulus
            if k < size:
                out[k] = (out[k] + term) % modulus
            else:
                out[k - size] = (out[k - size] + term * c) % modulus
    return out


def eval_poly_paterson_stockmeyer(coeffs, value, c1, modulus):
    degree = len(coeffs) - 1
    block = ceil((degree + 1) ** 0.5)
    size = len(value)

    value_pows = [[0] * size for _ in range(block)]
    value_pows[0][0] = 1
    for i in range(1, block):
        value_pows[i] = mul_mod_xe_minus_c(value_pows[i - 1], value, c1, modulus)

    giant = mul_mod_xe_minus_c(value_pows[block - 1], value, c1, modulus)

    grouped = []
    for start in range(0, degree + 1, block):
        acc = [0] * size
        for j, coeff in enumerate(coeffs[start : start + block]):
            if not coeff:
                continue
            power = value_pows[j]
            for idx, pv in enumerate(power):
                if pv:
                    acc[idx] = (acc[idx] + coeff * pv) % modulus
        grouped.append(acc)

    out = [0] * size
    for chunk in reversed(grouped):
        out = mul_mod_xe_minus_c(out, giant, c1, modulus)
        for i, val in enumerate(chunk):
            if val:
                out[i] = (out[i] + val) % modulus
    return out


def trim(poly):
    poly = poly[:]
    while poly and poly[-1] == 0:
        poly.pop()
    return poly


def poly_mod(f, g, modulus):
    f = trim(f)
    g = trim(g)
    while f and len(f) >= len(g):
        scale = f[-1] * pow(g[-1], -1, modulus) % modulus
        delta = len(f) - len(g)
        for i, coeff in enumerate(g):
            f[delta + i] = (f[delta + i] - scale * coeff) % modulus
        f = trim(f)
    return f


def poly_gcd(f, g, modulus):
    f = trim(f)
    g = trim(g)
    while g:
        f, g = g, poly_mod(f, g, modulus)
    inv = pow(f[-1], -1, modulus)
    return [coeff * inv % modulus for coeff in f]


def flint_poly_gcd(poly_f, poly_g, modulus):
    while poly_g != 0:
        _, rem = divmod(poly_f, poly_g)
        poly_f, poly_g = poly_g, rem
    lead = int(poly_f[poly_f.degree()])
    return poly_f * pow(lead, -1, modulus)


def flint_eval_paterson_stockmeyer(ctx, coeffs, value, modulus_poly):
    degree = len(coeffs) - 1
    block = ceil((degree + 1) ** 0.5)

    powers = [ctx([1])]
    for _ in range(1, block):
        powers.append(powers[-1].mul_mod(value, modulus_poly))
    giant = powers[-1].mul_mod(value, modulus_poly)

    chunks = []
    zero = ctx([0])
    for start in range(0, degree + 1, block):
        acc = zero
        for j, coeff in enumerate(coeffs[start : start + block]):
            if coeff:
                acc += ctx([coeff]) * powers[j]
        chunks.append(acc % modulus_poly)

    out = zero
    for chunk in reversed(chunks):
        out = out.mul_mod(giant, modulus_poly)
        out += chunk
        out %= modulus_poly
    return out


def recover_secret(n, a, leak, out1, out2):
    coeffs_u = build_resultant_coeffs(out2, leak, n)

    a_e = pow(a, E, n)
    u_of_x = [0] * E
    u_of_x[0] = a_e * (1 + out1) % n
    choose = 1
    for k in range(1, E):
        choose = choose * (E - k + 1) // k
        u_of_x[k] = a_e * choose % n

    if flint is not None:
        ctx = flint.fmpz_mod_poly_ctx(n)
        base_poly = ctx([(-out1) % n] + [0] * (E - 1) + [1])
        eliminated_poly = flint_eval_paterson_stockmeyer(ctx, coeffs_u, ctx(u_of_x), base_poly)
        factor = flint_poly_gcd(base_poly, eliminated_poly, n)
        if factor.degree() != 1:
            raise ValueError(f"unexpected gcd degree: {factor.degree()}")
        x1 = (-int(factor[0])) % n
    else:
        eliminated = eval_poly_paterson_stockmeyer(coeffs_u, u_of_x, out1, n)
        base = [(-out1) % n] + [0] * (E - 1) + [1]
        factor = poly_gcd(base, eliminated, n)
        if len(factor) != 2:
            raise ValueError(f"unexpected gcd degree: {len(factor) - 1}")
        x1 = (-factor[0]) % n

    bound = 1 << 1024
    d = None

    residue_small = x1 % a
    small_count = max(1, (bound - 1 - residue_small) // a + 1) if residue_small < bound else 0
    for k in range(small_count):
        candidate = residue_small + k * a
        if candidate < bound and pow(candidate, E, n) == leak:
            d = candidate
            break

    if d is None:
        residue = (-x1) % a
        near_count = max(1, (bound - 1 - residue) // a + 1) if residue < bound else 0
        for k in range(near_count):
            small = residue + k * a
            if small < bound:
                candidate = n - small
                if pow(candidate, E, n) == leak:
                    d = candidate
                    break

    if d is None:
        raise ValueError("failed to recover d from x1")

    return ((x1 - d) * pow(a, -1, n) - 1) % n


def parse_challenge():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    file = sock.makefile("rwb", buffering=0)

    n = int(file.readline().decode().split("=", 1)[1].strip())
    _ = int(file.readline().decode().split("=", 1)[1].strip())
    file.readline()

    leak_line = file.readline().decode().split(":", 1)[1].strip()
    a, leak = ast.literal_eval(leak_line)
    out1 = int(file.readline().decode().split(":", 1)[1].strip())
    out2 = int(file.readline().decode().split(":", 1)[1].strip())
    return sock, file, n, a, leak, out1, out2


def main():
    sock, file, n, a, leak, out1, out2 = parse_challenge()
    secret = recover_secret(n, a, leak, out1, out2)
    guess = secret.to_bytes(64, "big").hex().encode()
    file.write(guess + b"\n")
    print(file.readline().decode(errors="ignore").strip())
    sock.close()


if __name__ == "__main__":
    main()
```

### ocean

task.py

```python
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import signal
import os

FLAG = os.getenv("FLAG", "xmctf{fake_flag}")
class MLFSR:
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


class LFSR(MLFSR):
    def __init__(self, n, seed, mask):
        super().__init__(n, seed, mask, lfsr=None)


signal.alarm(60)

secret = f'fakeflag{{{os.urandom(16).hex()}}}'

n = 64
seed = getRandomNBitInteger(n)
mask1, mask2 = getRandomNBitInteger(n), getRandomNBitInteger(n)
lfsr1 = LFSR(n, seed, mask1)
lfsr2 = MLFSR(n, seed, mask2, lfsr1)
print(f"mask1 = {mask1}")
print(f"mask2 = {mask2}")
print(f"output = {sum(lfsr2() << (n - 1 - i) for i in range(n))}")
print(f"enc = {AES.new(key=md5(str(seed).encode()).digest(), mode=AES.MODE_ECB).encrypt(pad(secret.encode(), 16)).hex()}")

if input('> ') == secret:
    print('🤭:', FLAG)
```

就很算法啊这个题

有两个64位的LFSR(lfsr1、lfsr2)，共享一个初始seed

lfsr1输出1则lfsr2就update，反之停那，调用lfsr2的64次，得到64bit输出，组成一个整数输出给你

我们要求解的话，我们可以先算lfsr1每走一步的输出行向量，再算lfsr2每走m步后的第k次输出的行向量，然后把输出切割，把未知的“每一步是否更新”转换为"每个小段更新了多少次"，这样就能把对 seed 的约束重新写回线性 GF(2)，然后算法去写枚举什么的求seed

ai的代码又臭又长，就不放了

### ez_random

task.py

```python
import patcher
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from secret import SEED , flag

ROUNDS = 40
N_BITS = 988
N_PAIRS = 37
N = 2**31 - 1
get_limit =  lambda i:  N - (1 * N // 3) * (1 - 0**(i == 10))



for i in range(ROUNDS):
    t = input('🤔 Please give me an option > ')

    if t == '1':
        set_random_seed(int.from_bytes(SEED, 'big'))

        pairs = [(getrandbits(N_BITS), random_prime(get_limit(_))) for _ in range(1, N_PAIRS)]

        key0, key1 = map(list, zip(*pairs))


        shuffle(key0)
        print(f"Key Part A: {key0}")

        key1_list0 = [x[0] for x in key1]
        key1_list1 = [x[1] for x in key1]

        print(f"Key Part B{0}: {key1_list0}")
        print(f"Key Part B{1}: {key1_list1}")


    elif t == '2':
        set_random_seed(int.from_bytes(SEED, 'big'))

        for k in range(1, N_PAIRS):
            random_prime(int(input(f'😋 Give me the {k}th number: ')) ^ (getrandbits(N_BITS) ^ get_limit(k)))

        print("👏 Let's get the flag")
        SHA = SHA256.new()
        SHA.update(str(getrandbits(256)).encode())
        KEY = SHA.digest()
        cipher = AES.new(KEY, AES.MODE_ECB)
        flag = pad(flag.encode(), AES.block_size)
        print("Flag:", cipher.encrypt(flag))

    else:
        print("❌ Invalid input!")
        break

```

MT19937的题，提交的第 `k` 个输入会进入 `random_prime(x_k xor (a_k xor limit_k))`。如果让提交值恰好等于真实的 `a_k`，内部参数就会变成 `0`，被改过的 `random_prime(0)` 会直接异常。于是远程就泄露了一个严格的等值 oracle，可以逐位恢复被 `shuffle` 打乱后的 `Key Part A` 顺序。

然后去逆Random的128bit，然后求r就行了

solve.py

```python
import ast
import random
import re
import sys
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwn import context, remote

HOST = "nc1.ctfplus.cn"
PORT = 24570
PROMPT = b"option > "
NUMBER_PROMPT = b"number: "
N = 2**31 - 1
ORDERED_INDICES = [
    18,
    27,
    31,
    21,
    15,
    33,
    23,
    25,
    28,
    7,
    34,
    2,
    35,
    12,
    1,
    0,
    6,
    20,
    3,
    11,
    8,
    24,
    4,
    13,
    17,
    5,
    30,
    26,
    22,
    32,
    14,
    9,
    29,
    19,
    10,
    16,
]

context.log_level = "error"


def unshift_right(x, shift):
    result = x
    for _ in range(32):
        result = x ^ (result >> shift)
    return result & 0xFFFFFFFF


def unshift_left(x, shift, mask):
    result = x
    for _ in range(32):
        result = x ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF


def untemper(value):
    value = unshift_right(value, 18)
    value = unshift_left(value, 15, 0xEFC60000)
    value = unshift_left(value, 7, 0x9D2C5680)
    value = unshift_right(value, 11)
    return value & 0xFFFFFFFF


def invert_step(si, si227):
    x = si ^ si227
    mti1 = (x & 0x80000000) >> 31
    if mti1:
        x ^= 0x9908B0DF
    x = (x << 1) & 0xFFFFFFFF
    mti = x & 0x80000000
    mti1 = (mti1 + (x & 0x7FFFFFFF)) & 0xFFFFFFFF
    return mti, mti1


def init_genrand(seed):
    mt = [0] * 624
    mt[0] = seed & 0xFFFFFFFF
    for i in range(1, 624):
        mt[i] = (0x6C078965 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
    return mt


def recover_kj_from_ji(ji, ji1, index):
    const = init_genrand(19650218)
    key = ji - (const[index] ^ ((ji1 ^ (ji1 >> 30)) * 1664525))
    return key & 0xFFFFFFFF


def recover_ji_from_ii(ii, ii1, index):
    ji = (ii + index) ^ ((ii1 ^ (ii1 >> 30)) * 1566083941)
    return ji & 0xFFFFFFFF


def get_limit(index):
    return 2 * N // 3 if index == 10 else N


def start(host, port):
    io = remote(host, port)
    io.recvuntil(PROMPT)
    return io


def parse_list(text, label):
    match = re.search(rf"{re.escape(label)}: (\[[^\n]+\])", text)
    if match is None:
        raise RuntimeError(f"missing {label}: {text}")
    return ast.literal_eval(match.group(1))


def fetch_option1(io):
    io.sendline(b"1")
    blob = io.recvuntil(PROMPT, drop=True)
    text = blob.decode("utf-8", "ignore")
    a = parse_list(text, "Key Part A")
    b0 = parse_list(text, "Key Part B0")
    b1 = parse_list(text, "Key Part B1")
    return a, b0, b1


def run_option2(io, ordered_values):
    io.sendline(b"2")
    for value in ordered_values:
        io.sendlineafter(NUMBER_PROMPT, str(value).encode())

    text = io.recvuntil(PROMPT, drop=True).decode("utf-8", "ignore")
    for line in text.splitlines():
        if line.startswith("Flag:"):
            return ast.literal_eval(line.split("Flag:", 1)[1].strip())
    raise RuntimeError(text)


def recover_python_seed(ordered_a, b1):
    words = {}
    position = 0
    for round_index, value in enumerate(ordered_a, start=1):
        limbs = [(value >> (32 * limb)) & 0xFFFFFFFF for limb in range(30)]
        for offset, limb in enumerate(limbs):
            if position + offset < 624:
                words[position + offset] = limb
        position += 31 + b1[round_index - 1]

    recoverable_i = {}
    for index in range(228, 624):
        required = [index, index - 227, index - 1, index - 228]
        if not all(pos in words for pos in required):
            continue
        si = untemper(words[index])
        si227 = untemper(words[index - 227])
        sim1 = untemper(words[index - 1])
        sim228 = untemper(words[index - 228])
        msb_i, _ = invert_step(si, si227)
        _, low31_i = invert_step(sim1, sim228)
        recoverable_i[index] = (msb_i | low31_i) & 0xFFFFFFFF

    votes = {0: {}, 1: {}, 2: {}, 3: {}}
    for index in range(230, 624):
        if not all(pos in recoverable_i for pos in (index, index - 1, index - 2)):
            continue
        ii = recoverable_i[index]
        ii1 = recoverable_i[index - 1]
        ii2 = recoverable_i[index - 2]
        ji = recover_ji_from_ii(ii, ii1, index)
        ji1 = recover_ji_from_ii(ii1, ii2, index - 1)
        kj_raw = recover_kj_from_ji(ji, ji1, index)
        limb_index = (index - 1) % 4
        votes[limb_index][kj_raw] = votes[limb_index].get(kj_raw, 0) + 1

    raw_limbs = [max(votes[i], key=votes[i].get) for i in range(4)]
    limbs = [((raw_limbs[i] - i) & 0xFFFFFFFF) for i in range(4)]
    seed = sum(value << (32 * index) for index, value in enumerate(limbs))

    rng = random.Random(seed)
    replay = [rng.getrandbits(32) for _ in range(624)]
    if not all(replay[index] == value for index, value in words.items()):
        raise RuntimeError("recovered seed does not replay observed words")
    return seed


def is_prime(value):
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def derive_key_from_seed(python_seed, ordered_a, b0, b1):
    rng = random.Random(python_seed)
    replay_b0 = []
    replay_b1 = []
    for round_index, expected_a in enumerate(ordered_a, start=1):
        if rng.getrandbits(988) != expected_a:
            raise RuntimeError(f"A mismatch at round {round_index}")
        limit = get_limit(round_index)
        attempts = 0
        while True:
            candidate = rng.randint(0, limit - 1)
            attempts += 1
            if candidate >= 2 and is_prime(candidate):
                replay_b0.append(candidate)
                replay_b1.append(attempts)
                break
    if replay_b0 != b0 or replay_b1 != b1:
        raise RuntimeError("replayed B0/B1 do not match observation")

    r_value = rng.getrandbits(256)
    key = sha256(str(r_value).encode()).digest()
    return r_value, key


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    io = start(host, port)
    try:
        observed_a, b0, b1 = fetch_option1(io)
        ordered_a = [observed_a[index] for index in ORDERED_INDICES]
        ciphertext = run_option2(io, ordered_a)
    finally:
        io.close()

    python_seed = recover_python_seed(ordered_a, b1)
    _, key = derive_key_from_seed(python_seed, ordered_a, b0, b1)
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)
    print(plaintext.decode())


if __name__ == "__main__":
    main()
```

### Whisper Line

apk+流量包xd

第一开始没逆明白，骗你的，其实流量包第一开始差点看sb了

流量包可以提出来一堆数据，分析apk，rsa加密，无padding，逆so发现N写成12进制数后构造成了F(x)，并且在Z(x)下可以分解？那么x=12时就可以求出pq

exp.py

```python
E = 65537
N = int(

    16,
)

A = {
    0: 1, 1: 1, 3: 1, 4: 2, 5: 2, 6: 2, 8: 2, 9: 2, 10: 2, 12: 1, 14: 2,
    15: 1, 16: 2, 17: 1, 18: 1, 20: 2, 21: 2, 23: 1, 24: 1, 25: 2, 27: 1,
    29: 2, 31: 2, 33: 2, 34: 2, 35: 2, 36: 2, 37: 2, 38: 1, 39: 1, 285: 1,
}
B = {0: 1, 40: 2, 120: 1, 200: 2, 240: 2, 280: 1, 285: 1}
CTS = [
]

p = sum(c * 12**i for i, c in A.items())
q = sum(c * 12**i for i, c in B.items())
d = pow(E, -1, (p - 1) * (q - 1))

for ct in CTS:
    m = pow(int.from_bytes(bytes.fromhex(ct)[::-1], "big"), d, N)
    s = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    if "part" in s and "=" in s:
        print(s.split("=", 1)[1].strip(), end="")
print()
```

## 总结

题目质量很高的，感觉现在题目趋势是越来越难，越来越融合甚至是主动加点脑洞进去？

后ai时代的趋势大概就是这样，害，感觉自己已经跟不上了xd。。。。。。。。
