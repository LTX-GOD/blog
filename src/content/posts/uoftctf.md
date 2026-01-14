---
title: UOFTCTF2026
published: 2026-01-13
pubDate: 2026-01-13
description: UOFTCTF2026 crypto wp
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

放假了很久没玩ctf了，打打国际赛恢复一下状态，下面很多exp都是官方的，原因是没存exp，存的写的太丑了（

## 题目

### leaked-d

task

```
n1=144193923737869044259998596038292537217126517072587407189785154961344425600188709243733103713567903690926695626210849582322575275021963176688615503362430255878068025864333805901831356111202249176714839010151878345993886718863579928588098080351940561045688931786378656665718140998014299097023143181095121810219

e1=65537

d1=12574092103116126584156918631595005114605155027996964036950457918490065036621732354668884564796078087090438462300608898225025828108557296714458055780952572974382089675780912070693778415852291145766476219909978391880801604060224785419022793121117332853938170749724540897211958251465747669952580590146500249193

e2=6767671

c=31703515320997441500407462163885912085193988887521686491271883832485018463764003313655377418478488372329742364292629844576532415828605994734718987367062694340608380583593689052813716395874850039382743513756381017287371000882358341440383454299152364807346068866304481227367259672607408256375720022838698292966

```

d泄露的题，直接分解

exp.py

```python
from Crypto.Util.number import long_to_bytes
from random import randint
from math import gcd

n1=
e1=65537
d1=

e2=6767671
c=

solution_not_found = True

while solution_not_found:
    k = d1 * e1 - 1
    g = randint(2, n1 - 1)
    t = k

    while t % 2 == 0:
        t = t // 2
        x = pow(g, t, n1)

        if x > 1 and gcd(x - 1, n1) > 1:
            p = gcd(x - 1, n1)
            q = n1 // p
            solution_not_found = False
            break

phi = (p-1)*(q-1)

d2 = pow(e2, -1, phi)

p = pow(c, d2, n1)

print(long_to_bytes(p))
```

### Gambler's Fallacy

task.py

```python
import random
from datetime import datetime
import hashlib
import hmac

class DiceGame():
    def __init__(self):
        self.balance = 800
        self.client_seed = "1337awesome"
        self.nonce = 0
        self.running = True
        with open("./serverseed", 'r') as f:
            random.seed(f.read())

    def roll_dice(self) -> int:
        self.server_seed = random.getrandbits(32)
        nonce_client_msg = f"{self.client_seed}-{self.nonce}".encode()
        sig = hmac.new(str(self.server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()
        index = 0
        lucky = int(sig[index*5:index*5+5], 16)
        while (lucky >= 1e6):
            index += 1
            lucky = int(sig[index * 5:index * 5 + 5], 16)
            if (index * 5 + 5 > 129):
                lucky = 9999
                break
        return round((lucky % 1e4) * 1e-2)

    def show_starting_banner(self) -> None:
        print(f"Balance: {self.balance}")
        print("options: ")
        print(" a) view shop ")
        print(" b) gamble ")
        print(" c) set own seed ")
        print(" d) exit ")

    def gamble_game(self) -> None:
        print("ULTIMATE BET WIN BIG MONEY!!!")
        wager = float(input(f"Wager per game (min-wager is {self.balance/800}): "))
        if (wager < self.balance/800 or wager > self.balance):
            print("Wager not in range!")
            return
        games = int(input("Number of games (int): "))
        greed = float(input("Enter your number higher or equal to the roll between 2-98 (prize improves with lower numbers): ")) # win if number is between 0 and n
        if (greed < 2 or greed > 98):
            print("Greed not in range!")
            return
        confirm = input("Do you wish to proceed? (Y/N)")
        if confirm == "Y":
            for i in range(games):
                if (self.balance - wager >= 0):
                    roll = self.roll_dice()
                    multiplier = (100-1)/(greed)
                    self.balance -= wager
                    reward_value = 0
                    if (greed >= roll):
                        reward_value = wager * multiplier
                    print(f"Game {i:05}: Roll: {roll:02}, Reward: {reward_value}, Nonce: {self.nonce}, Client-Seed: {self.client_seed}, Server-Seed: {self.server_seed}")
                    self.nonce+=1
                    self.balance += reward_value
                else:
                    print(f"Out of Balance...")
                    break
            print(f"Final Balance: {self.balance}")

    def game(self) -> None:
        while self.running:
                self.show_starting_banner()
                option = input("> ")
                match option:
                    case "a":
                        print("-- SHOP --")
                        print("a) buy flag : $10000")
                        print("b) exit")
                        choice = input("> ")
                        if (choice == "a") and (self.balance >= 10000):
                            with open("./flag", 'r') as f:
                                print(f.read())
                    case "b":
                        try:
                            self.gamble_game()
                        except Exception as e:
                            print("Error: ", e)
                    case "c":
                        print(f"current seed: {self.client_seed}")
                        self.client_seed = input("Set custom seed: ")
                    case "d":
                        self.running = False
                        break
                    case _:
                        print("unknown command..")

dicegame : DiceGame = DiceGame()
dicegame.game()
```

ai一把梭了这个，主要就是模拟这个逻辑去预测就行了，主要是写交互代码

exp.py

```python

import hashlib
import hmac
import re

from randcrack import RandCrack

from pwn import *

# 配置连接信息
HOST = '34.162.20.138'
PORT = 5000

# 本地模拟服务端的 roll_dice 逻辑
def get_predicted_roll(server_seed, client_seed, nonce):
    nonce_client_msg = f"{client_seed}-{nonce}".encode()
    # 计算 HMAC
    sig = hmac.new(str(server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()

    index = 0
    lucky = int(sig[index*5:index*5+5], 16)
    while (lucky >= 1e6):
        index += 1
        lucky = int(sig[index * 5:index * 5 + 5], 16)
        if (index * 5 + 5 > 129):
            lucky = 9999
            break
    return round((lucky % 1e4) * 1e-2)

def solve():
    # context.log_level = 'debug' # 如果需要调试可以取消注释
    io = remote(HOST, PORT)
    rc = RandCrack()

    client_seed = "1337awesome"
    current_nonce = 0

    print("[*] Connected via Pwntools")

    # === 第一阶段：收集 624 个 Server Seeds ===
    print("[*] Phase 1: Harvesting 624 server seeds to recover PRNG state...")

    # 进入 Gamble 模式
    io.sendlineafter(b'> ', b'b')

    # 赌注: 1 (最小), 局数: 624, Greed: 90 (为了稍微回点血保持余额，虽然输赢无所谓)
    io.sendlineafter(b'Wager per game', b'1')
    io.sendlineafter(b'Number of games', b'624')
    io.sendlineafter(b'Enter your number', b'90')
    io.sendlineafter(b'Do you wish to proceed? (Y/N)', b'Y')

    # 接收并解析输出
    for i in range(624):
        line = io.recvline().decode().strip()
        # 解析 Server-Seed
        match = re.search(r'Server-Seed: (\d+)', line)
        if match:
            seed_val = int(match.group(1))
            rc.submit(seed_val)
            current_nonce += 1
        else:
            print(f"Error parsing line: {line}")

    print("[+] State recovered! Engine is now synchronized.")

    # 解析当前余额
    final_balance_line = io.recvline().decode() # "Final Balance: xxx"
    current_balance = float(final_balance_line.split(":")[1].strip())
    print(f"[*] Current Balance: {current_balance}")

    # === 第二阶段：预测并赢取资金 ===
    print("[*] Phase 2: Exploiting via prediction...")

    while current_balance < 10000:
        # 1. 预测下一个 Server Seed
        predicted_server_seed = rc.predict_getrandbits(32)

        # 2. 本地计算结果
        predicted_roll = get_predicted_roll(predicted_server_seed, client_seed, current_nonce)

        # 3. 制定策略
        # 我们需要 greed >= roll 才能赢。赔率是 (100-1)/greed。
        # 为了最大化收益，greed 应该尽可能小，但必须 >= roll。
        # 游戏限制 greed 范围 2-98。

        target_greed = max(2, predicted_roll)

        # 如果预测结果是 99 (极其罕见)，greed 最大只能 98，必输。
        # 或者如果我们非常有信心，可以直接梭哈。

        wager = current_balance

        # 如果必输 (roll > 98)，只下最小注烧掉这个随机数
        if predicted_roll > 98:
            print(f"[-] Predicted bad roll ({predicted_roll}). Skipping with min bet.")
            wager = max(1, current_balance / 800) # 保持最小下注
            target_greed = 98
        else:
            print(f"[+] Predicted Roll: {predicted_roll}. Betting ALL-IN with Greed: {target_greed}")

        # 发起单局游戏
        io.sendlineafter(b'> ', b'b')
        io.sendlineafter(b'Wager per game', str(wager).encode())
        io.sendlineafter(b'Number of games', b'1')
        io.sendlineafter(b'Enter your number', str(target_greed).encode())
        io.sendlineafter(b'Do you wish to proceed? (Y/N)', b'Y')

        # 读取结果
        result_line = io.recvline().decode()
        if "Reward" in result_line:
            print(f"   -> Result: {result_line.strip()}")
            current_nonce += 1

        balance_line = io.recvline().decode()
        current_balance = float(balance_line.split(":")[1].strip())
        print(f"   -> New Balance: {current_balance}")

    # === 第三阶段：购买 Flag ===
    print("[*] Phase 3: Buying Flag...")
    io.sendlineafter(b'> ', b'a') # Enter shop
    io.sendlineafter(b'> ', b'a') # Buy flag
    io.interactive()
if __name__ == "__main__":
    solve()
```

### UofT LFSR Labyrinth

filter_cipher.py

```python
import itertools

# WG-style transformation ANF on 7 variables (x0..x6).
WG_ANF_TERMS = [
    (1, 2, 3, 4, 5, 6),
    (0, 1, 2, 3, 5),
    (0, 1, 2, 4, 5),
    (0, 1, 3, 4, 5),
    (1, 2, 3, 4, 5),
    (0, 1, 2, 4, 6),
    (0, 2, 3, 4, 6),
    (1, 2, 3, 4, 6),
    (0, 1, 2, 5, 6),
    (0, 2, 3, 5, 6),
    (1, 2, 3, 5, 6),
    (0, 3, 4, 5, 6),
    (1, 3, 4, 5, 6),
    (0, 1, 2, 4),
    (0, 1, 2, 5),
    (1, 2, 3, 5),
    (0, 1, 4, 5),
    (1, 3, 4, 5),
    (2, 3, 4, 5),
    (1, 2, 3, 6),
    (0, 1, 4, 6),
    (1, 2, 4, 6),
    (0, 3, 4, 6),
    (1, 3, 4, 6),
    (1, 2, 5, 6),
    (0, 3, 5, 6),
    (1, 4, 5, 6),
    (2, 4, 5, 6),
    (3, 4, 5, 6),
    (0, 1, 2),
    (0, 1, 4),
    (0, 2, 4),
    (1, 2, 4),
    (0, 1, 5),
    (0, 3, 5),
    (1, 3, 5),
    (2, 3, 5),
    (3, 4, 5),
    (0, 1, 6),
    (0, 3, 6),
    (2, 3, 6),
    (3, 4, 6),
    (0, 5, 6),
    (2, 5, 6),
    (4, 5, 6),
    (2, 3),
    (3, 4),
    (0, 5),
    (3, 5),
    (1, 6),
    (3, 6),
    (4, 6),
    (0,),
    (3,),
    (5,),
    (6,),
]


def eval_anf(bits, terms):
    """Evaluate ANF given bits (tuple/list of 0/1) and list of monomial tuples."""
    acc = 0
    for mon in terms:
        prod = 1
        for idx in mon:
            prod &= bits[idx]
            if prod == 0:
                break
        acc ^= prod
    return acc


class NLFFilterCipher:
    """
    Bit-level LFSR with nonlinear filter function.
    state[0] is the newest bit; shift inserts feedback at position 0 and drops the last bit.
    """

    def __init__(self, feedback_taps, filter_taps, state_bits):
        self.feedback_taps = tuple(feedback_taps)
        self.filter_taps = tuple(filter_taps)
        self.L = len(state_bits)
        self.state = list(state_bits)

    def clock(self):
        """Clock once, update state, and return keystream bit."""
        taps = [self.state[i] for i in self.filter_taps]
        z = eval_anf(taps, WG_ANF_TERMS)
        fb = 0
        for idx in self.feedback_taps:
            fb ^= self.state[idx]
        self.state = [fb] + self.state[:-1]
        return z

    def keystream(self, n):
        return [self.clock() for _ in range(n)]
```

crypto.py

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_key(state_bits, length=32):
    data = bytes(state_bits)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b"nlfg-ctf")
    return hkdf.derive(data)


def encrypt(flag: bytes, state_bits):
    key = derive_key(state_bits, length=32)
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, flag, associated_data=None)
    return nonce, ct


def decrypt(nonce, ct, state_bits):
    key = derive_key(state_bits, length=32)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct, associated_data=None)
```

还有一个json数据文件，就不放了，初看这个就是z3一把梭的东西，搓了个脚本，发现时间太久了，跑不出来，找ai问问优化方法，`Annihilator`这个方法还是tql，以前没有听过都，然后sat求解

官方exp.py

```python
"""
solver.

It does four steps:
1) Read public data (taps, keystream, filter ANF).
2) Build one small annihilator polynomial for z=0 and z=1 (degree <= 3).
3) Encode the LFSR + annihilator equations to CNF and solve with SAT.
4) Derive the key from the recovered 48-bit state and decrypt.
"""

import json
from itertools import combinations
from pathlib import Path
from pysat.formula import CNF, IDPool
from pysat.solvers import Glucose4
import crypto


def eval_anf(bits, terms):
    """Evaluate the filter ANF on a 7-bit vector."""
    acc = 0
    for mon in terms:
        prod = 1
        for i in mon:
            prod &= bits[i]
            if not prod:
                break
        acc ^= prod
    return acc


def build_annihilator(filter_terms, target_side):
    """
    Return one degree<=3 annihilator polynomial for the 7-bit filter.
    target_side=1: polynomial vanishes when f=1 (use with z=1)
    target_side=0: polynomial vanishes when f=0 (use with z=0)
    """
    mons = [()]
    for d in range(1, 4):
        mons += list(combinations(range(7), d))

    # truth table of f
    f_tt = []
    for mask in range(1 << 7):
        bits = [(mask >> i) & 1 for i in range(7)]
        f_tt.append(eval_anf(bits, filter_terms))

    # Build rows (bitmasks of monomials that evaluate to 1) where f == target_side.
    rows = []
    for mask, val in enumerate(f_tt):
        if val != target_side:
            continue
        bits = [(mask >> i) & 1 for i in range(7)]
        row = 0
        for j, mon in enumerate(mons):
            v = 1
            for i in mon:
                v &= bits[i]
                if not v:
                    break
            if v:
                row |= 1 << j
        rows.append(row)

    def nullspace_basis(rows, ncols):
        """Simple GF(2) row reduction to get a basis of the nullspace."""
        rows = rows[:]
        pivots = {}
        r = 0
        for c in range(ncols):
            pr = next((i for i in range(r, len(rows)) if (rows[i] >> c) & 1), None)
            if pr is None:
                continue
            rows[r], rows[pr] = rows[pr], rows[r]
            pivot_row = rows[r]
            pivots[c] = pivot_row
            for i in range(len(rows)):
                if i != r and ((rows[i] >> c) & 1):
                    rows[i] ^= pivot_row
            r += 1
            if r == len(rows):
                break

        pivot_cols = set(pivots.keys())
        free_cols = [c for c in range(ncols) if c not in pivot_cols]
        pivot_items = sorted(pivots.items(), reverse=True)

        basis = []
        for fcol in free_cols:
            vec = 1 << fcol
            for c, row in pivot_items:
                other = row & ~(1 << c)
                parity = (other & vec).bit_count() % 2
                if parity:
                    vec |= 1 << c
                else:
                    vec &= ~(1 << c)
            basis.append(vec)
        return basis, mons

    basis, mons = nullspace_basis(rows, len(mons))
    vec = basis[0]
    poly = [mons[i] for i in range(len(mons)) if (vec >> i) & 1]
    return poly


def solve_instance(data):
    L = data["L"]
    fb = data["feedback_taps"]
    ftaps = data["filter_taps"]
    terms = [tuple(t) for t in data["filter_terms"]]
    ks = data["keystream"]

    # Single annihilator per side (degree <=3).
    ann_f = build_annihilator(terms, target_side=1)
    ann_f1 = build_annihilator(terms, target_side=0)

    pool = IDPool(start_from=L + 1)
    cnf = CNF()

    # b[t]: state[0]=b[t], state[1]=b[t-1], ...
    tmin, tmax = - (L - 1), len(ks)
    b = {t: pool.id() for t in range(tmin, tmax + 1)}

    def and2(a, bvar):
        # o = a AND bvar
        o = pool.id()
        cnf.extend([[-a, -bvar, o], [a, -o], [bvar, -o]])
        return o

    def xor2(a, bvar):
        # o = a XOR bvar
        o = pool.id()
        cnf.extend([[-a, -bvar, -o], [-a, bvar, o], [a, -bvar, o], [a, bvar, -o]])
        return o

    def xor_chain(vs):
        if len(vs) == 1:
            return vs[0]
        cur = vs[0]
        for v in vs[1:]:
            cur = xor2(cur, v)
        return cur

    # LFSR recurrence: b[t+1] = xor(feedback taps)
    for t in range(0, len(ks)):
        taps = [b[t - off] for off in fb]
        eq = xor_chain([b[t + 1]] + taps)
        cnf.append([-eq])  # XOR(...) == 0

    # Annihilator equations per timestep (pick annihilator based on keystream bit)
    for t, z in enumerate(ks):
        taps = [b[t - off] for off in ftaps]
        poly = ann_f if z == 1 else ann_f1
        rhs = 0
        mon_vars = []
        for mon in poly:
            if len(mon) == 0:
                rhs ^= 1
            elif len(mon) == 1:
                mon_vars.append(taps[mon[0]])
            else:
                cur = taps[mon[0]]
                for idx in mon[1:]:
                    cur = and2(cur, taps[idx])
                mon_vars.append(cur)
        eq = xor_chain(mon_vars)
        cnf.append([eq] if rhs else [-eq])

    # Direct keystream checks to prune spurious solutions.
    check_count = min(40, len(ks))
    for t in range(check_count):
        taps = [b[t - off] for off in ftaps]
        rhs = 0
        mon_vars = []
        for mon in terms:
            if len(mon) == 0:
                rhs ^= 1
            elif len(mon) == 1:
                mon_vars.append(taps[mon[0]])
            else:
                cur = taps[mon[0]]
                for idx in mon[1:]:
                    cur = and2(cur, taps[idx])
                mon_vars.append(cur)
        zvar = xor_chain(mon_vars)
        want = ks[t] ^ rhs
        cnf.append([zvar] if want else [-zvar])

    solver = Glucose4(bootstrap_with=cnf.clauses)
    assert solver.solve()
    model = set(solver.get_model())

    def val(var):
        return 1 if var in model else 0

    state_bits = [val(b[-i]) for i in range(0, L)]
    return state_bits


def main():
    data = json.load(open("challenge.json"))
    state_bits = solve_instance(data)
    pt = crypto.decrypt(bytes.fromhex(data["nonce"]), bytes.fromhex(data["ct"]), state_bits)
    print(pt.decode())


if __name__ == "__main__":
    main()
```

### MAT247

chall.py

```python
import numpy as np
import galois
from secret import gen_commuting_matrix
from Crypto.Util.number import *
from Crypto.Random import random
GF = galois.GF(202184226278391025014930169562408816719)


A = GF([])

FLAG = b'uoftctf{fake_flag}'

bits = bin(bytes_to_long(FLAG))[2:].zfill(8*len(FLAG))

for b in bits:
    if b=='0':
        print(gen_commuting_matrix(A))
    else:
        print(np.linalg.matrix_power(A, random.randrange(202184226278391025014930169562408816719**12-1)))

```

还有一个output.txt，太长了不写

题目其实给了个提示`If V admits a T-cyclic vector, and ST=TS, show that S = p(T) for some polynomial T.`

我们主要目的是映射回去，然后求解，如果不太懂，让ai讲一下这个原理就行

exp.py

```python
import re
from Crypto.Util.number import *
import tqdm

p = 202184226278391025014930169562408816719
F = GF(p)

V = VectorSpace(F, 12)

A = Matrix(F, [])

K = GF(p^12, modulus=A.characteristic_polynomial(), name='x')

x = K.gen()

v = vector(F, (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

basis = [v]
for i in range(1, 12):
    basis.append(A*basis[-1])

Binv = Matrix(basis).transpose().inverse()

# generated with AI because I do NOT want to parse my own creations myself.
def parse_pretty_matrix(s):
    """
    Parse a matrix written in the Sage/NumPy pretty format:

    [[ a b c
       d e f ]
     [ g h i ]]

    Returns a Sage Matrix over ZZ.
    """

    # Remove outer whitespace
    s = s.strip()

    # Sanity check
    if not (s.startswith("[[") and s.endswith("]]")):
        raise ValueError("Input does not look like a matrix")

    # Extract row blocks: anything between [ ... ]
    # but not the outermost brackets
    row_strings = re.findall(r"\[([^\[\]]+)\]", s)

    rows = []
    for row in row_strings:
        # Split on whitespace and parse integers
        entries = [ZZ(x) for x in row.split()]
        rows.append(entries)

    # Check rectangularity
    ncols = len(rows[0])
    for r in rows:
        if len(r) != ncols:
            raise ValueError("Non-rectangular matrix")

    return Matrix(ZZ, rows).change_ring(F)

def parse_all_pretty_matrices(s):
    """
    Parse multiple pretty-printed matrices back-to-back.

    Returns a list of Matrix(ZZ).
    """

    mats = []
    i = 0
    n = len(s)

    while i < n:
        # Find start of matrix
        start = s.find("[[", i)
        if start == -1:
            break

        depth = 0
        j = start

        # Find matching closing brackets
        while j < n:
            if s[j:j+2] == "[[":
                depth += 1
                j += 2
            elif s[j:j+2] == "]]":
                depth -= 1
                j += 2
                if depth == 0:
                    break
            else:
                j += 1

        block = s[start:j]

        mats.append(parse_pretty_matrix(block))
        i = j

    return mats

with open("../dist/output.txt") as f:
    data = f.read()

Ms = parse_all_pretty_matrices(data)
# The rest is written by me, not the clanker.
print("Parsed matrices")
bits = []


# Technically you could just do this all in the matrix field but that's just unecessarily expensive...
o = p^12-1
small_primes = []
for d in Primes()[:100]:
    if o%d==0:
        small_primes.append(d)

fac = 1
for d in small_primes:
    while o%d==0:
        if x^(o//d)==1:
            o//=d
        else:
            break

print(x^o)

for M in tqdm.tqdm(Ms):
    P = Binv*(M*v)
    #print(Polynomial(P)(A)==M)
    y = K(P)
    if (y^o)==1:
        bits.append(1)
    else:
        bits.append(0)

print(long_to_bytes(int(''.join(map(str, bits)), 2)))
```

### Orca

task.py

```python
#!/usr/bin/env python3
import os, sys, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BS=16
FLAG=open("flag.txt","rb").read().strip()
M=256
L=1024

def pad(m):
    p=BS-(len(m)%BS)
    return m+bytes([p])*p

class O:
    def __init__(self):
        self.k=get_random_bytes(16)
        self.pl=int.from_bytes(os.urandom(1),"big")%97
        n=L//BS+1
        self.n=n
        self.q=list(range(n))
        for i in range(n-1,0,-1):
            j=int.from_bytes(os.urandom(2),"big")%(i+1)
            self.q[i],self.q[j]=self.q[j],self.q[i]

    def e(self, idx, u):
        if idx<0 or idx>=self.n:
            return None
        u=u[:M]
        p=os.urandom(self.pl)
        m=p+u+FLAG
        if len(m)>L:
            m=m[:L]
        else:
            m+=os.urandom(L-len(m))
        c=AES.new(self.k,AES.MODE_ECB).encrypt(pad(m))
        b=[c[i:i+BS] for i in range(0,len(c),BS)]
        out=[b[i] for i in self.q]
        return out[idx]

o=O()

while True:
    sys.stdout.write("> ")
    sys.stdout.flush()
    l=sys.stdin.readline()
    if not l:
        break
    l=l.strip()
    if not l:
        print("error")
        continue
    if l.lower() == "exit":
        break
    if ":" in l:
        a,h=l.split(":",1)
    else:
        parts=l.split(None,1)
        if len(parts)==1:
            a,h=parts[0],""
        else:
            a,h=parts[0],parts[1]
    try:
        idx=int(a,10)
        u=bytes.fromhex(h) if h else b""
    except Exception:
        print("error")
        continue
    blk=o.e(idx,u)
    if blk is None:
        print("error")
    else:
        print(base64.b64encode(blk).decode())

```

类似AES-ECB的思想，首先我们对齐块，找到开头，因为题目进行了置换操作，我们可以标记一块，然后发送两个这样的标记块，然后找到重复出现的，然后就可以确定这是第几块了，然后逐字节爆破，思路给ai，一把梭了

exp.py

```python
#!/usr/bin/env python3
from pwn import *
import base64, os, re
from collections import Counter

context.log_level = "error"

HOST, PORT = "34.186.247.84", 5000
BS = 16
FLAG_RE = re.compile(rb"uoftctf\{[^}]+\}")

def oracle_connect():
    r = remote(HOST, PORT)
    r.recvuntil(b"> ")
    return r

def q(r, idx: int, data: bytes) -> bytes | None:
    line = f"{idx}:{data.hex()}".encode()
    r.sendline(line)
    resp = r.recvline().strip()
    r.recvuntil(b"> ")
    if resp == b"error":
        return None
    return base64.b64decode(resp)

def discover_nblocks(r, limit=256) -> int:
    for i in range(limit):
        if q(r, i, b"") is None:
            return i
    raise Exception("failed to discover nblocks")

def get_all_blocks(r, nblocks: int, data: bytes):
    return [q(r, i, data) for i in range(nblocks)]

def find_align_pad(r, nblocks: int) -> int:
    for pad in range(BS):
        pt = b"C"*pad + b"A"*(3*BS) + b"D"*BS
        bl = get_all_blocks(r, nblocks, pt)
        c = Counter(bl)
        if any(v >= 3 for v in c.values()):
            return pad
    raise Exception("align_pad not found")

def find_marker_ct(r, nblocks: int, align_pad: int, marker=b"Z"*BS) -> bytes:
    pt = b"C"*align_pad + marker + os.urandom(BS) + marker + os.urandom(BS)
    bl = get_all_blocks(r, nblocks, pt)
    c = Counter(bl)
    dups = [b for b, v in c.items() if v >= 2]
    if not dups:
        raise Exception("marker_ct not found")
    dups.sort(key=lambda x: c[x], reverse=True)
    return dups[0]

def find_out_index_for_t(r, nblocks: int, align_pad: int, marker_ct: bytes, t: int, marker=b"Z"*BS) -> int:
    pt = b"C"*align_pad + os.urandom(BS*t) + marker + os.urandom(BS*2)
    for i in range(nblocks):
        b = q(r, i, pt)
        if b == marker_ct:
            return i
    raise Exception("failed to locate marker output index")

def solve():
    r = oracle_connect()
    nblocks = discover_nblocks(r)
    align_pad = find_align_pad(r, nblocks)
    marker_ct = find_marker_ct(r, nblocks, align_pad)

    pos_cache = {}
    recovered = b""
    i = 0

    while True:
        fill = BS - 1 - (i % BS)
        t = (fill + i) // BS

        if t not in pos_cache:
            pos_cache[t] = find_out_index_for_t(r, nblocks, align_pad, marker_ct, t)
        idx = pos_cache[t]

        target = q(r, idx, b"C"*align_pad + b"A"*fill)
        if target is None:
            raise Exception("unexpected error on probe")

        base = b"C"*align_pad + b"A"*fill + recovered
        found = None
        for g in range(256):
            b = q(r, idx, base + bytes([g]))
            if b == target:
                found = g
                break

        if found is None:
            raise Exception(f"dictionary miss at byte {i}")

        recovered += bytes([found])
        i += 1

        print(f"Recovered {i} bytes: {recovered!r}")

        m = FLAG_RE.search(recovered)
        if m:
            print(m.group(0).decode())
            return

if __name__ == "__main__":
    solve()
```

### Rotor Cipher

task.py

```python
import numpy as np
import string
import secrets

try:
    from rotor_design import RX, RY, RZ, Ref
    is_placeholder = False
except:
    # Placeholders
    RX = ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q")
    RY = ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E")
    RZ = ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V")
    Ref = [('A','Y'), ('B','R'), ('C','U'), ('D','H'), ('E','Q'), ('F','S'),
           ('G','L'), ('I','P'), ('J','X'), ('K','N'), ('M','O'), ('T','Z'),
           ('V','W')]
    is_placeholder = True
N = 26
ALPHA = string.ascii_uppercase

# helper function for formatting the flag
# please check that your wirings are consistent with the provided
# log before submitting.
def format_flag(RX, RY, RZ, Ref):
    # ignore notches
    assert all(map(lambda c : c in ALPHA, RX[0])) and \
           all(map(lambda c : c in ALPHA, RY[0])) and \
           all(map(lambda c : c in ALPHA, RZ[0]))
    x_rotor = "".join(RX[0])
    y_rotor = "".join(RY[0])
    z_rotor = "".join(RZ[0])
    # reflector should be cannonical
    assert all(map(lambda t : len(t) == 2 and ord(t[0]) < ord(t[1]), Ref))
    assert Ref == sorted(Ref)
    ref_str = "_".join(map("".join, Ref))
    return "uoftctf{{{}_{}_{}_{}}}".format(x_rotor, y_rotor, z_rotor, ref_str)

if is_placeholder:
    # This is the placeholder flag for the fake wirings
    # Please generate the flag for the real wirings
    # You lose aura if you submit this flag, we can see the submitted flags
    assert format_flag(RX, RY, RZ, Ref) == "uoftctf{EKMFLGDQVZNTOWYHXUSPAIBRCJ_AJDKSIRUXBLHWTMCQGZNPYFVOE_BDFHJLCPRTXVZNYEIWGAKMUSQO_AY_BR_CU_DH_EQ_FS_GL_IP_JX_KN_MO_TZ_VW}"

def idx(c):
    return ord(c) - ord("A")

class Rotor:
    def __init__(self, R, init_pos):
        rotor_perm, turn_notch = R
        assert sorted(rotor_perm) == list(ALPHA)
        rotor_perm = list(map(idx, rotor_perm))
        self.rotor_perm = np.eye(N, dtype=int)[rotor_perm]
        self.turn_notch = idx(turn_notch)
        assert init_pos in ALPHA
        self.pos = idx(init_pos)

    def rotate(self):
        propagate = self.pos == self.turn_notch
        self.pos = (self.pos + 1) % N
        return propagate

    def curr_perm(self):
        idx = (np.arange(N, dtype=int) + self.pos) % N
        return self.rotor_perm[np.ix_(idx, idx)].T

class Involution:
    def __init__(self, P):
        # check canonical
        assert all(map(lambda t : len(t) == 2 and ord(t[0]) < ord(t[1]), P))
        assert P == sorted(P)
        involution_perm = np.arange(N, dtype=int)
        for u,v in P:
            u = idx(u)
            v = idx(v)
            involution_perm[u], involution_perm[v] = involution_perm[v], involution_perm[u]
        self.involution_perm = np.eye(N, dtype=int)[involution_perm]
        assert (self.involution_perm @ self.involution_perm == np.eye(N, dtype=int)).all()

    def perm(self):
        return self.involution_perm.T

class RotorCipher:
    def __init__(self, Ref, R, P, R0):
        self.plugboard = Involution(P)
        self.rotors = [Rotor(*r_r0) for r_r0 in zip(R, R0)]
        self.reflector = Involution(Ref)

    def encrypt(self, s):
        # Note: decryption is the same as encryption
        t = ""
        for c in s:
            for i in range(len(self.rotors)):
                if not self.rotors[i].rotate():
                    break
            vec = np.zeros(N, dtype=int)
            vec[ALPHA.index(c)] = 1
            vec = self.plugboard.perm() @ vec
            for i in range(len(self.rotors)):
                vec = self.rotors[i].curr_perm() @ vec
            vec = self.reflector.perm() @ vec
            for i in range(len(self.rotors)-1, -1, -1):
                vec = np.linalg.inv(self.rotors[i].curr_perm()) @ vec
            vec = self.plugboard.perm() @ vec
            t += ALPHA[np.argmax(vec)]
        return t


if __name__ == "__main__":
    if is_placeholder:
        print("Using placeholder rotor wiring.")
    sample_plaintext = "The quick brown fox jumps over the lazy dog"
    sample_plaintext = sample_plaintext.upper().replace(" ", "")
    sample_setting = ["O", "J", "B"]
    sample_plugboard = [("B", "P"), ("C", "D"), ("F", "W"), ("N", "X"), ("S", "V"), ("U", "Y")]
    cipher = RotorCipher(Ref, [RX, RY, RZ], sample_plugboard, sample_setting)
    sample_ciphertext = cipher.encrypt(sample_plaintext)
    cipher = RotorCipher(Ref, [RX, RY, RZ], sample_plugboard, sample_setting)
    sample_decrypt = cipher.encrypt(sample_ciphertext)
    print("Sample Plaintext:", sample_plaintext)
    print("Sample Ciphertext:", sample_ciphertext)
    print("Sample Decrypt:", sample_decrypt)
    assert sample_plaintext == sample_decrypt
    print("Begin Challenge Log")
    DAYS = 10
    MESSAGES = 100
    rng = secrets.SystemRandom()
    rotors = {"X": RX, "Y": RY, "Z": RZ}
    letters = list(ALPHA)
    for d in range(DAYS):
        # random rotor order
        rotor_order = ["X", "Y", "Z"]
        rng.shuffle(rotor_order)
        # random plugboard
        rng.shuffle(letters)
        plugboard = []
        for i in range(6):
            t = (letters[2*i], letters[2*i+1])
            plugboard.append((min(t), max(t)))
        plugboard.sort()
        # random setting
        rng.shuffle(letters)
        setting = letters[:3]
        print("{}: rotor: {}, plugboard: {} setting: {}".format(d, rotor_order, plugboard, setting))
        for m in range(MESSAGES):

            # random message
            message = "".join(rng.choice(letters) for i in range(6))
            cipher = RotorCipher(Ref, list(map(rotors.get, rotor_order)), plugboard, setting)
            ct = cipher.encrypt(message)
            print("    {:2}: msg: {} ct: {}".format(m, message, ct))
```

还有一个数据文件就不放了

Enigma Machine的实现，我们明文攻击就行

exp.py

```python
import itertools
import string
import sys
sys.path.append("..")
import rotor_cipher

ALPHA = string.ascii_uppercase
N = 26

def idx(c):
    return ord(c) - ord("A")

def alp(i):
    return chr(i + ord("A"))

def ac(a, b):
    L = []
    for c in a:
        L.append(b[idx(c)])
    return L

def acr(*args):
    if len(args) == 1:
        return args[0]
    else:
        return ac(args[0], acr(*args[1:]))

def P(k):
    k = k % N
    return list(ALPHA[k:] + ALPHA[:k])

def inv(p):
    L = [None]*N
    for i in range(N):
        L[idx(p[i])] = chr(i + ord("A"))
    return L

def make_involution(swaps):
    L = list(ALPHA)
    for swap in swaps:
        assert L[idx(swap[0])] == swap[0] and L[idx(swap[1])] == swap[1]
        L[idx(swap[0])], L[idx(swap[1])] = L[idx(swap[1])], L[idx(swap[0])]
    return L

def cycles_of(p):
    seen = [False] * N
    cycles = []
    for i in range(N):
        if seen[i]:
            continue
        # find orbit starting at i
        cur = i
        orbit = []
        while not seen[cur]:
            seen[cur] = True
            orbit.append(cur)
            cur = idx(p[cur])
        cycles.append(orbit)
    return cycles

def group_cycles_by_length(cycles):
    groups = {}
    for cycle in cycles:
        if len(cycle) not in groups:
            groups[len(cycle)] = []
        groups[len(cycle)].append(cycle)
    return groups

def build_conjugators_sigma1_sigma0(sigma0, sigma1):
    c0 = group_cycles_by_length(cycles_of(sigma0))
    c1 = group_cycles_by_length(cycles_of(sigma1))

    V = [-1] * N
    used_y = [False] * N
    results = []

    lengths = sorted(c0.keys())

    def try_assign_cycle(cyc0, cyc1, rot):
        L = len(cyc0)
        newly = []
        for j, x in enumerate(cyc0):
            y = cyc1[(j + rot) % L]
            if V[x] != -1 and V[x] != y:
                # conflict
                for xx in newly:
                    used_y[V[xx]] = False
                    V[xx] = -1
                return None
            if V[x] == -1:
                if used_y[y]:
                    for xx in newly:
                        used_y[V[xx]] = False
                        V[xx] = -1
                    return None
                V[x] = y
                used_y[y] = True
                newly.append(x)
        return newly

    def undo(newly):
        for x in newly:
            used_y[V[x]] = False
            V[x] = -1

    def recurse_length(li):
        if li == len(lengths):
            results.append(V.copy())
            return

        L = lengths[li]
        list0 = c0[L]
        list1 = c1[L]

        for perm_list1 in itertools.permutations(list1):
            # recurse through cycles within this length group
            def recurse_cycle(ci):
                if ci == len(list0):
                    recurse_length(li + 1)
                    return
                cyc0 = list0[ci]
                cyc1 = perm_list1[ci]
                for rot in range(len(cyc0)):
                    newly = try_assign_cycle(cyc0, cyc1, rot)
                    if newly is None:
                        continue
                    recurse_cycle(ci + 1)
                    undo(newly)

            recurse_cycle(0)

    recurse_length(0)
    return results

def parse_daily_log(s):
    perms = [[None for _ in range(26)] for _ in range(6)]
    for row in s.split("\n")[1:]:
        msg_pos = row.index("msg: ") + 5
        msg = row[msg_pos:msg_pos+6]
        ct_pos = row.index("ct: ") + 4
        ct = row[ct_pos:ct_pos+6]
        for i in range(6):
            assert perms[i][idx(msg[i])] is None or perms[i][idx(msg[i])] == ct[i]
            perms[i][idx(msg[i])] = ct[i]
    for i in range(6):
        if perms[i].count(None) == 1:
            perms[i][perms[i].index(None)] = list(set(ALPHA) - set(perms[i]))[0]
    return perms

def solve_fast_rotor(A, s, init_pos):
    B = []
    for i in range(6):
        B.append(acr(P(-(i+1)), s, A[i], s, P(i+1)))
    C = []
    for i in range(5):
        C.append(ac(B[i], B[i+1]))
    candidates = build_conjugators_sigma1_sigma0(C[0], C[1])
    solutions = []
    for candidate in candidates:
        accepted = True
        for i in range(len(C)-1):
            s = C[i]
            t = C[i + 1]
            for x in range(N):
                if candidate[idx(s[x])] != idx(t[candidate[x]]):
                    accepted = False
        if accepted:
            solutions.append(list(map(alp, candidate)))
    assert len(solutions) == 1
    candidate_rotors = []
    for off in range(26):
        R = [None] * N
        x = "A"
        for c in P(off):
            R[idx(x)] = c
            x = solutions[0][idx(x)]
        R = ac(P(-idx(init_pos)), R)
        candidate_rotors.append(R)
    return candidate_rotors

def involution_perm_to_swaps(perm):
    L = []
    for i in range(N):
        if perm[i] > alp(i):
            L.append((alp(i), perm[i]))
    return L

x_right_log =
x_s = make_involution([('B', 'R'), ('C', 'D'), ('H', 'K'), ('I', 'X'), ('M', 'Q'), ('Y', 'Z')])
x_A = parse_daily_log(x_right_log)
# save setting for later reflector solving
x_setting = ['Y', 'Q', 'B']
# fix missing
x_A[1][20] = 'I'
x_A[1][22] = 'Q'
x_A[5][5] = 'N'
x_A[5][20] = 'U'
x_rotor_cands = solve_fast_rotor(x_A, x_s, 'Y')
print("X candidates", list(map(lambda x:"".join(x), x_rotor_cands)))

y_right_log =
y_s = make_involution([('D', 'X'), ('H', 'I'), ('J', 'S'), ('N', 'Z'), ('O', 'R'), ('P', 'Y')])
y_A = parse_daily_log(y_right_log)
y_rotor_cands = solve_fast_rotor(y_A, y_s, 'J')
print("Y candidates", list(map(lambda x:"".join(x), y_rotor_cands)))

z_right_log =
z_s = make_involution([('B', 'P'), ('D', 'Z'), ('F', 'Q'), ('I', 'L'), ('J', 'M'), ('W', 'X')])
z_A = parse_daily_log(z_right_log)
z_rotor_cands = solve_fast_rotor(z_A, z_s, 'Q')
print("Z candidates", list(map(lambda x:"".join(x), z_rotor_cands)))

# find which rotor candidate
sample_plaintext = "The quick brown fox jumps over the lazy dog"
sample_plaintext = sample_plaintext.upper().replace(" ", "")
sample_setting = ["O", "J", "B"]
sample_plugboard = [("B", "P"), ("C", "D"), ("F", "W"), ("N", "X"), ("S", "V"), ("U", "Y")]
target = "ZRMQPAFSYCICFLJSGQPPRAFRTEUEOCXDWVQ"

# first solve for exact x rotor and notch position using sample
iy = 0
iz = 0
for ix, notch in itertools.product(range(N), repeat=2):

    reflector_perm = acr(P(idx(x_setting[2])), inv(z_rotor_cands[iz]), P(-(idx(x_setting[2]))),
                    P(idx(x_setting[1])), inv(y_rotor_cands[iy]), P(-(idx(x_setting[1]))),
                    P(idx(x_setting[0])+1), inv(x_rotor_cands[ix]), P(-(idx(x_setting[0])+1)),
                    x_s, x_A[0], x_s,
                    P(idx(x_setting[0])+1), x_rotor_cands[ix], P(-(idx(x_setting[0])+1)),
                    P(idx(x_setting[1])), y_rotor_cands[iy], P(-idx(x_setting[1])),
                    P(idx(x_setting[2])), z_rotor_cands[iz], P(-idx(x_setting[2])))
    reflector = involution_perm_to_swaps(reflector_perm)

    RX = (x_rotor_cands[ix], alp(notch))
    RY = (y_rotor_cands[iy], "A")
    RZ = (z_rotor_cands[iz], "A")
    cipher = rotor_cipher.RotorCipher(reflector, [RX, RY, RZ], sample_plugboard, sample_setting)
    sample_ciphertext = cipher.encrypt(sample_plaintext)
    if sample_ciphertext == target:
        print("ix, notch:", ix, alp(notch))
        break
# now that we have x rotor, let us solve y and z rotors
ix = 25
x_notch = 'R'

sample_plaintext = "RXEZYG"
sample_setting = ['M', 'G', 'D']
sample_plugboard = [('A', 'G'), ('F', 'P'), ('J', 'Z'), ('K', 'W'), ('R', 'U'), ('S', 'X')]
target = "BTXSQY"

for iy, iz in itertools.product(range(26), repeat=2):
    reflector_perm = acr(P(idx(x_setting[2])), inv(z_rotor_cands[iz]), P(-(idx(x_setting[2]))),
                    P(idx(x_setting[1])), inv(y_rotor_cands[iy]), P(-(idx(x_setting[1]))),
                    P(idx(x_setting[0])+1), inv(x_rotor_cands[ix]), P(-(idx(x_setting[0])+1)),
                    x_s, x_A[0], x_s,
                    P(idx(x_setting[0])+1), x_rotor_cands[ix], P(-(idx(x_setting[0])+1)),
                    P(idx(x_setting[1])), y_rotor_cands[iy], P(-idx(x_setting[1])),
                    P(idx(x_setting[2])), z_rotor_cands[iz], P(-idx(x_setting[2])))
    reflector = involution_perm_to_swaps(reflector_perm)

    RX = (x_rotor_cands[ix], x_notch)
    RY = (y_rotor_cands[iy], "A")
    RZ = (z_rotor_cands[iz], "A")
    cipher = rotor_cipher.RotorCipher(reflector, [RZ, RY, RX], sample_plugboard, sample_setting)
    sample_ciphertext = cipher.encrypt(sample_plaintext)
    if sample_ciphertext == target:
        print(ix, iy, iz)
        print(RX, RY, RZ)
        print(reflector)
        print("Candidate flag:", rotor_cipher.format_flag(RX, RY, RZ, reflector))
```

这个当时还真不咋会）

### MAT347

task.py

```python
from sage.all import *
from Crypto.Util.number import *
import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

#https://std.neuromancer.sk/nist/P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)

x = bytes_to_long(os.urandom(32))
Q = x*G
print(Q.xy())

def h(m):
    return bytes_to_long(sha256(m.encode()).digest())

class RNG:
    def __init__(self):
        self.cnt = bytes_to_long(os.urandom(32))
        self.mod = 2**256
    def next(self, m):
        res = h(str(self.cnt))
        a = 0 if m is None else h(m)
        self.cnt = (self.cnt+1+a)%self.mod
        return res


def sign(m, rng):
    z = h(m)
    k = rng.next(m)
    r = int((k*G).x())
    s = ((pow(k, -1, E.order())*z+(x*r)))%E.order()
    return r, s

def exchange(rng):
    k = rng.next(None)
    msg = open("flag.txt", "rb").read()
    return AES.new(long_to_bytes(int((k*Q).x())%(2**128), blocksize=16), AES.MODE_CBC, iv=long_to_bytes(int((k*Q).x())>>128, blocksize=16)).encrypt(pad(msg, 16))

rng = RNG()

for z in range(670):
    choice = input("Sign or Exchange? ").lower().strip()
    if choice=="sign":
        m = input("Message: ")
        print(*sign(m, rng))
    elif choice=="exchange":
        print(exchange(rng).hex())
    else:
        print("Bad input")
```

ecdsa+DH+prng，按理来说这个是可以预测的，我第一开始的思路是650轮慢慢收集加尝试，每次都尝试一下，并且收集到最后尝试一次，结果太慢了，吃顿饭回来才三百多次

这种情况肯定是格问题了，收集所有的cnt

$$
\text{cnt}_{i+1} = (\text{cnt}_i + 1 + H(m)) \pmod{2^{256}}\\
\text{cnt}_n = \text{cnt}_0 + \sum_{i=1}^{n} (H(m_i) + 1) \pmod{2^{256}}\\
\text{exchanges} \times 1 + \sum_{i} \left( \text{freq}_i \times (H(m_i) + 1) \right) \equiv \text{Target} - \text{cnt}_0 \pmod{2^{256}}
$$

svp启动

exp.py

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
import random
from pwn import *
import ast

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


def h(m):
    return bytes_to_long(sha256(str(m).encode()).digest())+1

hs = list(map(h, range(25000)))


bestScore = Infinity
# This might take a couple minutes depending on your luck, but shouldn't take an unreasonable amount of time.
while bestScore>=670:
    smpl = random.sample(hs, k=72)
    M = Matrix(smpl+[2^256]).stack(Matrix.identity(n=72, ring=ZZ).augment(Matrix.zero(ncols=1, nrows=72, ring=ZZ))).stack(Matrix([1]*72+[0])).stack(Matrix.zero(ncols=73, nrows=1, ring=ZZ)).transpose().LLL().transpose()
    i = 50
    while i<90:
        L = M.augment(Matrix([-140]+[i]*72+[480]+[2000]).transpose())
        r = L.transpose()[-1]-L.transpose().LLL()[-1]
        if min(r[1:])>=0:
            break
        i+=1
    if min(r[1:])<0:
        continue
    score = r[-2]-r[0]
    if score<bestScore:
        bestSample = smpl
        currBest = r
        bestScore = score
        print(bestScore)

ms = list(map(hs.index, bestSample))
freqs = currBest[1:-2]
exchanges = -currBest[0]+1

print(ms)
print(freqs)
print(exchanges)

io = remote("104.196.21.25", 5000)
io.readline()
io.readline()
io.readline()
print(io.readline())
io.recvuntil(b'Solution? ')
POW = input()
io.sendline(POW.encode())
io.readline()
pub = ast.literal_eval(io.readline().decode().strip())

sigs = []

for m, f in zip(ms, freqs):
    m = str(m).encode()
    for j in range(f):
        io.sendline(b'sign')
        io.sendline(m)
        r, s = list(map(int, io.readline().strip().decode().split()[-2:]))
        sigs.append((r,s))

for i in range(exchanges):
    io.sendline(b'exchange')
    sigs.append(bytes.fromhex(io.readline().strip().decode().split()[-1]))



r, s = sigs[0]
z = h(ms[0])-1

R = E.lift_x(Integer(r))
for R in (R, -R):
    S = (s*R-z*G)*pow(r, -1, E.order())
    print(AES.new(long_to_bytes(int(S.x())%(2**128), blocksize=16), AES.MODE_CBC, iv=long_to_bytes(int(S.x())>>128, blocksize=16)).decrypt(sigs[-1]))
```

## 总结

质量挺高的，题目其实不算特别简单，最后一个ai应该不会吧（，快快恢复状态
