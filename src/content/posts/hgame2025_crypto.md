---
title: Hgame2025_crypto
published: 2025-02-19
pinned: false
description: Hgame2025，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-19
pubDate: 2025-02-19
---


## week1

### sieve

task

```
from Crypto.Util.number import bytes_to_long
from sympy import nextprime

FLAG = b'hgame{xxxxxxxxxxxxxxxxxxxxxx}'
m = bytes_to_long(FLAG)

def trick(k):
    if k > 1:
        mul = prod(range(1,k)) 
        if k - mul % k - 1 == 0:
            return euler_phi(k) + trick(k-1) + 1
        else:
            return euler_phi(k) + trick(k-1)
    else:
        return 1

e = 65537
p = q = nextprime(trick(e^2//6)<<128)
n = p * q
enc = pow(m,e,n)
print(f'{enc=}')
```

trick计算的是小于k的所有数的欧拉函数之和加上素数的个数
这个k - mul % k - 1 == 0成立代表此时为素数(威尔逊定理)
实现可以用sage里面的phi，这里都用cpp写了，快一点

```
#include <iostream>
#include <vector>
#include <cmath>
using namespace std;
typedef long long ll;

int main() {
    ll n = 715849728;
    vector<bool> isPrime(n, true);
    isPrime[0] = isPrime[1] = false;

    // 处理2的倍数
    for (ll j = 4; j < n; j += 2) {
        isPrime[j] = false;
    }

    // 只处理奇数
    for (ll i = 3; i * i <= n; i += 2) {
        if (isPrime[i]) {
            for (ll j = i * i; j < n; j += 2 * i) {
                isPrime[j] = false;
            }
        }
    }

    ll count = 0;
    for (ll i = 2; i < n; i++) {
        if (isPrime[i]) {
            count++;
        }
    }

    cout << count << endl;
    return 0;
}

//37030583

#include <cstdio>
#include <iostream>
#define ll long long
using namespace std;
const int N = 1e7 + 1;
ll phi[N + 10], prime[N + 10];
int tot;
bool mark[N + 10];
void getphi(int n)
{
    phi[1] = 1;
    for (int i = 2; i <= n; i++)
    {
        if (!mark[i])
        {
            prime[++tot] = i;
            phi[i] = i - 1; // 性质1
        }
        for (int j = 1; j <= tot && i * prime[j] <= n; j++)
        {
            mark[i * prime[j]] = 1;
            if (!(i % prime[j]))
            {
                phi[i * prime[j]] = phi[i] * prime[j]; // 性质2
                break;
            }
            else
                phi[i * prime[j]] = phi[i] * (prime[j] - 1);
        }
    }

    for (int i = 2; i <= n; i++)
        phi[i] += phi[i - 1];
}
ll work(int n)
{
    if (n <= N)
        return phi[n];
    ll ans = 0;
    int pos;
    for (int i = 2; i <= n; i = pos + 1)
    {
        pos = n / (n / i); // 向下取整，很长一段是相同的
        ans += (pos - i + 1) * work(n / i);
    }
    return (ll)n * (n + 1) / 2 - ans;
}
int main()
{
    int n = 715849728;
    getphi(N);
    printf("%lld", work(n));
    return 0;
}

// 155763335410704472

```
然后去求解flag
```
from Crypto.Util.number import *
from sympy import nextprime

e = 65537
trick_result = 155763335410704472+37030583

p = q = nextprime(trick_result<<128)
n=p**2
phi=p**2-p
enc=2449294097474714136530140099784592732766444481665278038069484466665506153967851063209402336025065476172617376546
d=inverse(e,phi)
print(long_to_bytes(int(pow(enc,d,n))))
```

### ezbag

task
```
from Crypto.Util.number import *
import random
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad
from secrets import flag

list = []
bag = []
p=random.getrandbits(64)
assert len(bin(p)[2:])==64
for i in range(4):
    t = p
    a=[getPrime(32) for _ in range(64)]
    b=0
    for i in a:
        temp=t%2
        b+=temp*i
        t=t>>1
    list.append(a)
    bag.append(b)
print(f'list={list}')
print(f'bag={bag}')

key = hashlib.sha256(str(p).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = pad(flag,16)
ciphertext = cipher.encrypt(flag)
print(f"ciphertext={ciphertext}")
```

本来想着直接用通杀，直接构造试试，发现出不来，估计是密度问题，给两组数据应该也是因为这个，那么就把第二组数据扔最下面新的一行，用BKZ即可
看stone的wp，好像还有更简单的方法，我也写上来
```
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
list=
bag=
ciphertext=
L=Matrix(ZZ,65,68)
for i in range(64):
    L[i,i]=2
    L[i,-1]=list[0][-i-1]
    L[i,-2]=list[1][-i-1]
    L[i,-3]=list[2][-i-1]
    L[i,-4]=list[3][-i-1]
L[-1,:]=1
L[-1,-1]=bag[0]
L[-1,-2]=bag[1]
L[-1,-3]=bag[2]
L[-1,-4]=bag[3]
x=L.BKZ()
print(x[0])
p=''
for i in x[0][:64]:
    if i==x[0][0]:
        p+='1'
    else:
        p+='0'
p=int(p,2)
key = hashlib.sha256(str(p).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(ciphertext)
print(flag)


'''
            |           |
|p0 p1 ...|*|a0 a1 a2 a3| = |b0 b1 ...|
            |           |
'''
 
A= matrix(ZZ,list).T
B= matrix(ZZ,bag)
M= block_matrix(ZZ,[[1,A],[0,B]])
 
v = M.BKZ()
a = -1*v[-1]
p =  int(''.join(map(str,a[:-4][::-1])),2)
#17739748707559623655
key = hashlib.sha256(str(p).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
cipher.decrypt(ciphertext)

```

### surperrsa

好像是中间改了一次题？
task
```
from Crypto.Util.number import *
import random
from sympy import prime

FLAG=b'hgame{xxxxxxxxxxxxxxxxxx}'
e=0x10001

def primorial(num):
    result = 1
    for i in range(1, num + 1):
        result *= prime(i)
    return result
M=primorial(random.choice([39,71,126]))

def gen_key():
    while True:
        k = getPrime(random.randint(20,40))
        a = getPrime(random.randint(20,60))
        p = k * M + pow(e, a, M)
        if isPrime(p):
            return p

p,q=gen_key(),gen_key()
n=p*q
m=bytes_to_long(FLAG)
enc=pow(m,e,n)

print(f'{n=}')
print(f'{enc=}')
```

改了之后就是最经典的roca问题啦，直接用脚本，改一下参数就行，微调一下

```
#roca脚本
from Crypto.Util.number import *
## Coppersmith-howgrave
def coppersmith_howgrave(f, N, beta, m, t, R):
    #Check if parameters are within bounds
    assert 0 < beta <= 1, 'beta not in (0, 1]'
    assert f.is_monic(), 'f is not monic'
    
    #get delta and the matrix dimension
    delta = f.degree()
    n = delta * m + t
    
    #Building the polynomials
    fZ = f.change_ring(ZZ) #change the ring from Zmod(N) to ZZ
    x = fZ.parent().gen()  #make x a variable in ZZ
    f_list = [] 
    for ii in range(m):
        for j in range(delta):
            #We want them ordered that's we have N^(m-ii1) and fZ^ii
            f_list.append(((x*R)^j) * N^(m-ii) * fZ(x*R)^(ii)) #the g_{i,j}
    for ii in range(t):
        f_list.append((x*R)^ii * fZ(x*R)^m) #the h_i
        
    #Build the lattice
    B = matrix(ZZ, n) # n = delta * m + t
    for ii in range(n):
        for j in range(ii+1):
            B[ii, j] = f_list[ii][j]
            
    #LLL it
    B_lll = B.LLL(early_red = True, use_siegel = True)

    #take the shortest vector to construct our new poly g
    g = 0
    for ii in range(n):
        g += x^ii * B_lll[0, ii] / R^ii
    
    #factor the polynomial
    potential_roots = g.roots()
    #print('potential roots:', potential_roots)
    
    #we don't need to do this Since our we test in our roca function
#     #test roots
#     roots = []
#     for r in potential_roots:
#         if r[0].is_integer():
#             res = fZ(ZZ(r[0]))
#             if gcd(N, res) >= N^beta:
#                 roots.append(ZZ(r[0]))
    #print('roots:', roots)
    return potential_roots
    #return roots
def roca(N, M_prime, g, m, t, beta):
    g = int(g)
    c_prime = discrete_log(Zmod(M_prime)(N), Zmod(M_prime)(g))
    ord_M_prime = Zmod(M_prime)(g).multiplicative_order()
    
    #search boundaries
    bottom = c_prime // 2 
    top =(c_prime + ord_M_prime) // 2 
    print('numbers to check',   top - bottom, ' between ', (bottom, top))

    
    #constants for coppersmith
    P.<x> = PolynomialRing(Zmod(N))
    epsilon = beta / 7
    X = floor(2 * N^beta / M_prime)
    
    #the search
    for i, a in enumerate(range(bottom, top)):
        if i % 1000 == 0: #count iterations
            print(i)
            
        #construct polynomial
        f = x + int((inverse_mod(M_prime, N)) * int(pow(g, a, M_prime)))

        #roots = f.small_roots(X, beta, epsilon) #coppersmith
        roots = coppersmith_howgrave(f, N, beta, m, t, X)
        #check solutions
        for k_prime, _ in roots:
            p = int(k_prime * M_prime) + int(pow(g, a, M_prime))
            if N % p == 0:
                return p, N//p
    return -1, -1
n=787190064146025392337631797277972559696758830083248285626115725258876808514690830730702705056550628756290183000265129340257928314614351263713241
e=65537

def get_M1_m_t_values(key_size):
    if 512 <= key_size < 1024:
        m = 5
        M1=0x1b3e6c9433a7735fa5fc479ffe4027e13bea
    elif 1024 <= key_size < 2048:
        m = 4
        M1=0x24683144f41188c2b1d6a217f81f12888e4e6513c43f3f60e72af8bd9728807483425d1e
    elif 2048 <= key_size < 3072:
        m = 6
        M1=0x016928dc3e47b44daf289a60e80e1fc6bd7648d7ef60d1890f3e0a9455efe0abdb7a748131413cebd2e36a76a355c1b664be462e115ac330f9c13344f8f3d1034a02c23396e6
    elif 3072 <= key_size < 4096:
        m = 25
    else:
        m = 7
    return M1,m, m+1
M_prime,m, t = get_M1_m_t_values(512)
p, q = roca(n, M_prime, e, m, t, .5) 
assert(p*q==n)
print(p)
print(q)
enc=365164788284364079752299551355267634718233656769290285760796137651769990253028664857272749598268110892426683253579840758552222893644373690398408
print(long_to_bytes(int(pow(enc,inverse_mod(e,(p-1)*(q-1)),n))))
```

## week2

### Ancient Recall
task
```
import random

Major_Arcana = ["The Fool", "The Magician", "The High Priestess","The Empress", "The Emperor", "The Hierophant","The Lovers", "The Chariot", "Strength","The Hermit", "Wheel of Fortune", "Justice","The Hanged Man", "Death", "Temperance","The Devil", "The Tower", "The Star","The Moon", "The Sun", "Judgement","The World"]
wands = ["Ace of Wands", "Two of Wands", "Three of Wands", "Four of Wands", "Five of Wands", "Six of Wands", "Seven of Wands", "Eight of Wands", "Nine of Wands", "Ten of Wands", "Page of Wands", "Knight of Wands", "Queen of Wands", "King of Wands"]
cups = ["Ace of Cups", "Two of Cups", "Three of Cups", "Four of Cups", "Five of Cups", "Six of Cups", "Seven of Cups", "Eight of Cups", "Nine of Cups", "Ten of Cups", "Page of Cups", "Knight of Cups", "Queen of Cups", "King of Cups"]
swords = ["Ace of Swords", "Two of Swords", "Three of Swords", "Four of Swords", "Five of Swords", "Six of Swords", "Seven of Swords", "Eight of Swords", "Nine of Swords", "Ten of Swords", "Page of Swords", "Knight of Swords", "Queen of Swords", "King of Swords"]
pentacles = ["Ace of Pentacles", "Two of Pentacles", "Three of Pentacles", "Four of Pentacles", "Five of Pentacles", "Six of Pentacles", "Seven of Pentacles", "Eight of Pentacles", "Nine of Pentacles", "Ten of Pentacles", "Page of Pentacles", "Knight of Pentacles", "Queen of Pentacles", "King of Pentacles"]
Minor_Arcana = wands + cups + swords + pentacles
tarot = Major_Arcana + Minor_Arcana
reversals = [0,-1]

Value = []
cards = []
YOUR_initial_FATE = []
while len(YOUR_initial_FATE)<5:
    card = random.choice(tarot)
    if card not in cards:
        cards.append(card)
        if card in Major_Arcana:
            k = random.choice(reversals)
            Value.append(tarot.index(card)^k)
            if k == -1:
                YOUR_initial_FATE.append("re-"+card)
            else:
                YOUR_initial_FATE.append(card)
        else:
            Value.append(tarot.index(card))
            YOUR_initial_FATE.append(card)
    else:
        continue
print("Oops!lets reverse 1T!")

FLAG=("hgame{"+"&".join(YOUR_initial_FATE)+"}").replace(" ","_")

YOUR_final_Value = Value

def Fortune_wheel(FATE):
    FATEd = [FATE[i]+FATE[(i+1)%5] for i in range(len(FATE))]
    return FATEd

for i in range(250):
    YOUR_final_Value = Fortune_wheel(YOUR_final_Value)
print(YOUR_final_Value)
YOUR_final_FATE = []
for i in YOUR_final_Value:
    YOUR_final_FATE.append(tarot[i%78])
print("Your destiny changed!\n",",".join(YOUR_final_FATE))
print("oh,now you GET th3 GOOd lU>k,^^")

"""
Oops!lets reverse 1T!
[2532951952066291774890498369114195917240794704918210520571067085311474675019, 2532951952066291774890327666074100357898023013105443178881294700381509795270, 2532951952066291774890554459287276604903130315859258544173068376967072335730, 2532951952066291774890865328241532885391510162611534514014409174284299139015, 2532951952066291774890830662608134156017946376309989934175833913921142609334]
Your destiny changed!
 Eight of Cups,Ace of Cups,Strength,The Chariot,Five of Swords
oh,now you GET th3 GOOd lU>k,^^
"""

```

感觉是纯纯的脚本题,上一个是abcde，下一个就是a+b,b+c,c+d,d+e,e+a，那么e+a-a-b+b+c-c-d+d+e=2e，一个一个还原就行了

```
Major_Arcana = ["The Fool", "The Magician", "The High Priestess", "The Empress", "The Emperor", "The Hierophant", "The Lovers", "The Chariot", "Strength", "The Hermit", "Wheel of Fortune", "Justice", "The Hanged Man", "Death", "Temperance", "The Devil", "The Tower", "The Star", "The Moon", "The Sun", "Judgement", "The World"]
Minor_Arcana = ["Ace of Wands", "Two of Wands", "Three of Wands", "Four of Wands", "Five of Wands", "Six of Wands", "Seven of Wands", "Eight of Wands", "Nine of Wands", "Ten of Wands", "Page of Wands", "Knight of Wands", "Queen of Wands", "King of Wands",
                "Ace of Cups", "Two of Cups", "Three of Cups", "Four of Cups", "Five of Cups", "Six of Cups", "Seven of Cups", "Eight of Cups", "Nine of Cups", "Ten of Cups", "Page of Cups", "Knight of Cups", "Queen of Cups", "King of Cups",
                "Ace of Swords", "Two of Swords", "Three of Swords", "Four of Swords", "Five of Swords", "Six of Swords", "Seven of Swords", "Eight of Swords", "Nine of Swords", "Ten of Swords", "Page of Swords", "Knight of Swords", "Queen of Swords", "King of Swords",
                "Ace of Pentacles", "Two of Pentacles", "Three of Pentacles", "Four of Pentacles", "Five of Pentacles", "Six of Pentacles", "Seven of Pentacles", "Eight of Pentacles", "Nine of Pentacles", "Ten of Pentacles", "Page of Pentacles", "Knight of Pentacles", "Queen of Pentacles", "King of Pentacles"]
tarot = Major_Arcana + Minor_Arcana

YOUR_final_Value = [2532951952066291774890498369114195917240794704918210520571067085311474675019,
                    2532951952066291774890327666074100357898023013105443178881294700381509795270,
                    2532951952066291774890554459287276604903130315859258544173068376967072335730,
                    2532951952066291774890865328241532885391510162611534514014409174284299139015,
                    2532951952066291774890830662608134156017946376309989934175833913921142609334]

def reverse_Fortune_wheel(FATEd):
    f0 = (FATEd[4] - FATEd[3] + FATEd[2] - FATEd[1] + FATEd[0]) // 2
    return [f0, FATEd[0] - f0, FATEd[1] - FATEd[0] + f0, FATEd[2] - FATEd[1] + FATEd[0] - f0, FATEd[3] - FATEd[2] + FATEd[1] - FATEd[0] + f0]

for _ in range(250):
    YOUR_final_Value = reverse_Fortune_wheel(YOUR_final_Value)

YOUR_initial_FATE = ['re-' + tarot[i ^ -1] if i < 0 else tarot[i] for i in YOUR_final_Value]
FLAG = f"hgame{{{'&'.join(YOUR_initial_FATE).replace(' ', '_')}}}"

print(FLAG)
```

### Intergalactic Bound
task
```
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint
import hashlib
from secrets import flag

def add_THCurve(P, Q):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 - y1 ** 2 * x2 * y2) * pow(a * x1 * y1 * x2 ** 2 - y2, -1, p) % p
    y3 = (y1 * y2 ** 2 - a * x1 ** 2 * x2) * pow(a * x1 * y1 * x2 ** 2 - y2, -1, p) % p
    return x3, y3


def mul_THCurve(n, P):
    R = (0, 0)
    while n > 0:
        if n % 2 == 1:
            R = add_THCurve(R, P)
        P = add_THCurve(P, P)
        n = n // 2
    return R


p = getPrime(96)
a = randint(1, p)
G = (randint(1,p), randint(1,p))

d = (a*G[0]^3+G[1]^3+1)%p*inverse(G[0]*G[1],p)%p

x = randint(1, p)
Q = mul_THCurve(x, G)
print(f"p = {p}")
print(f"G = {G}")
print(f"Q = {Q}")

key = hashlib.sha256(str(x).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = pad(flag,16)
ciphertext = cipher.encrypt(flag)
print(f"ciphertext={ciphertext}")

"""
p = 55099055368053948610276786301
G = (19663446762962927633037926740, 35074412430915656071777015320)
Q = (26805137673536635825884330180, 26376833112609309475951186883)
ciphertext=b"k\xe8\xbe\x94\x9e\xfc\xe2\x9e\x97\xe5\xf3\x04'\x8f\xb2\x01T\x06\x88\x04\xeb3Jl\xdd Pk$\x00:\xf5"
"""

```

先把a求出来，后面类似羊城杯,
https://tangcuxiaojikuai.xyz/post/689431.html

```

p = 55099055368053948610276786301
Gx, Gy = 19663446762962927633037926740, 35074412430915656071777015320
Qx, Qy = 26805137673536635825884330180, 26376833112609309475951186883
G = (19663446762962927633037926740, 35074412430915656071777015320)
Q = (26805137673536635825884330180, 26376833112609309475951186883)
ciphertext=b"k\xe8\xbe\x94\x9e\xfc\xe2\x9e\x97\xe5\xf3\x04'\x8f\xb2\x01T\x06\x88\x04\xeb3Jl\xdd Pk$\x00:\xf5"
from Crypto.Util.number import*
numerator = ((pow(Qy,3,p)+1)*Gx*Gy - (pow(Gy,3,p)+1)*Qx*Qy) % p
denominator = (pow(Gx,3,p)*Qx*Qy - pow(Qx,3,p)*Gx*Gy) % p
a = (numerator * pow(denominator, -1, p)) % p
print(a)

a=39081810733380615260725035189

d = (a*G[0]^3+G[1]^3+1)%p*inverse(G[0]*G[1],p)%p

R.<x,y,z> = Zmod(p)[]
cubic = a*x^3 + y^3 + z^3 - d*x*y*z
E = EllipticCurve_from_cubic(cubic,morphism=True)
P = E(G)
Q = E(Q)
r = 60869967041981
m = (r*Q).log(r*P)
from Crypto.Cipher import AES
import hashlib

key = hashlib.sha256(str(m).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = b"k\xe8\xbe\x94\x9e\xfc\xe2\x9e\x97\xe5\xf3\x04'\x8f\xb2\x01T\x06\x88\x04\xeb3Jl\xdd Pk$\x00:\xf5"
flag = cipher.decrypt(ciphertext)
print("Flag:", flag)

```

### SPiCa

task
```
from Crypto.Util.number import getPrime, long_to_bytes,bytes_to_long
from secrets import flag
from sage.all import *

def derive_M(n):
    iota=0.035
    Mbits=int(2 * iota * n^2 + n * log(n,2))
    M = random_prime(2^Mbits, proof = False, lbound = 2^(Mbits - 1))
    return Integer(M)

m = bytes_to_long(flag).bit_length()
n = 70
p = derive_M(n)

F = GF(p)
x = random_matrix(F, 1, n)
A = random_matrix(ZZ, n, m, x=0, y=2)
A[randint(0, n-1)] = vector(ZZ, list(bin(bytes_to_long(flag))[2:]))
h = x*A

with open("data.txt", "w") as file:
    file.write(str(m) + "\n")
    file.write(str(p) + "\n")
    for item in h:
        file.write(str(item) + "\n")
```

是一个hssp问题，用的https://0xffff.one/d/2077/6 ,没咋理解，但是会写题啦起码（）

```
from Crypto.Util.number import *

import logging
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(levelname)s] %(message)s"
)

# https://github.com/Neobeo/HackTM2023/blob/main/solve420.sage
# faster LLL reduction to replace `M.LLL()` wiith `flatter(M)`
def flatter(M, **kwds):
    from subprocess import check_output
    from re import findall
    M = matrix(ZZ,M)
    # compile https://github.com/keeganryan/flatter and put it in [imath:0]PATH
    z = '[[' + ']\n['.join(' '.join(map(str,row)) for row in M) + ']]'
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int,findall(b'-?\\d+', ret)))
def checkMatrix(M, wl=[-1, 1]):
  M = [list(_) for _ in list(M)]
  ml = list(set(flatten(M)))
  logging.debug(ml)
  return sorted(ml) == sorted(wl)

def Nguyen_Stern(h, m, n, M):
  B = matrix(ZZ, m)
  B[0, 0] = M
  h0i = Integer(h[0]).inverse_mod(M)
  for i in range(1, m):
    B[i, 0] = - h[i] * h0i
    B[i, i] = 1
  #L = B.BKZ()	# slooooooow
  L = flatter(B)
  logging.info('flatter done.')

  '''
  vh = vector(Zmod(M), h)
  logging.debug([vector(Zmod(M), list(l)) * vh  for l in L])
  '''

  Lxo = matrix(ZZ, L[:m-n])
  Lxc = Lxo.right_kernel(algorithm='pari').matrix() # faster
  logging.info('right_kernel done.')

  '''
  try:
    Lx_real = matrix(ZZ, [xi + [0] * (m - len(xi)) for xi in X])
    rsc = Lxc.row_space()
    logging.debug([xi in rsc for xi in Lx_real])
  except:
    pass
  '''

  e = matrix(ZZ, [1] * m)
  B = block_matrix([[-e], [2*Lxc]])
  Lx = B.BKZ()
  logging.info('BKZ done.')
  assert checkMatrix(Lx)
  assert len(set(Lx[0])) == 1

  Lx = Lx[1:]
  E = matrix(ZZ, [[1 for c in range(Lxc.ncols())] for r in range(Lxc.nrows())])
  Lx = (Lx + E) / 2

  Lx2 = []
  e = vector(ZZ, [1] * m)
  rsc = Lxc.row_space()
  for lx in Lx:
    if lx in rsc:
      Lx2 += [lx]
      continue
    lx = e - lx
    if lx in rsc:
      Lx2 += [lx]
      continue
    logging.warning('Something wrong?')
  Lx = matrix(Zmod(M), Lx2)

  vh = vector(Zmod(M), h)
  va = Lx.solve_left(vh)
  return Lx, va


m=247
n=70
M= 
h=
Lx, va = Nguyen_Stern(h, m, n, M)


for i in Lx:
  flag=''
  for j in i:
    flag+=str(j)
  flag=long_to_bytes(int(flag,2))
  if b'hgame' in flag:
    print(flag)

```

## 总结
题目质量真的挺高的，有些题第一开始不会写，想了好多才发现自己是zz，被自己蠢哭了