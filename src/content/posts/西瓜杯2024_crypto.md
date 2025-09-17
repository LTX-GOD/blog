---
title: 西瓜杯2024_crypto
published: 2024-12-12
pinned: false
description: 西瓜杯2024，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2024-12-12
pubDate: 2024-12-12
---


<h2>前言</h2>
额，好像是聚餐的时候才知道有这个比赛，打的时候已经要结束了，复现一下

&nbsp;
<h2>题目</h2>
<h3>奇奇怪怪的条形码</h3>
能隐隐约约看出来里面是字母和数字，一个一个写出来扔到随波逐流里面梭哈就行了。

&nbsp;
<h3>factor</h3>
task
<pre class="code">from Crypto.Util.number import *
import gmpy2
import os
from enc import flag

hint = os.urandom(36)
tmp = bytes_to_long(hint)
m = bytes_to_long(flag)
p = getPrime(512)
q = getPrime(512)
d = getPrime(400)
phi = (p-1)*(q-1)
e = gmpy2.invert(d,phi)
n = p*q
c = pow(m,e,n)
leak1 = p^tmp
leak2 = q^tmp
print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"leak1 = {leak1}")
print(f"leak2 = {leak2}")</pre>
思路

我们已知leak1=p^temp,leak2=q^temp,那么p^q=leak1^leak2，那么就变成了最经典的剪枝爆破，套用脚本就可以写出来了。貌似这个n可以直接分解，也可以写出来（）

&nbsp;

exp
<pre class="code">n=
e=
c=
leak1=
leak2=

from Crypto.Util.number import*

leak=leak1^leak2
leak_bits = 512
xor = bin(leak)[2:].zfill(512)
pq = []
def pq_high_xor(p="", q=""):
   lp, lq = len(p), len(q)
   tp0 = int(p + (512-lp) * "0", 2)
   tq0 = int(q + (512-lq) * "0", 2)
   tp1 = int(p + (512-lp) * "1", 2)
   tq1 = int(q + (512-lq) * "1", 2)
   if tp0 * tq0 &gt; n or tp1 * tq1 &lt; n:
      return
   if lp == leak_bits:
      pq.append(tp0)
      return
   if xor[lp] == "1":
      pq_high_xor(p + "0", q + "1")
      pq_high_xor(p + "1", q + "0")
   else:
      pq_high_xor(p + "0", q + "0")
      pq_high_xor(p + "1", q + "1")
pq_high_xor()
print(pq)

p=
q=

phi=(p-1)*(q-1)
d=inverse(e,phi)
m=pow(c,d,n)
print(long_to_bytes(m))</pre>
&nbsp;

&nbsp;
<h3>给你d又怎样</h3>
task
<pre class="code">from Crypto.Util.number import *
from gmpy2 import *

flag="ctfshow{***}"
m=bytes_to_long(flag.encode())
e=65537
p=getPrime(128)
q=getPrime(128)
n=p*q
phin=(p-1)*(q-1)
d=invert(e,phin)
c=pow(m,e,n)
print("c=",c)
print("hint=",pow(n,e,c))
print("e=",e)
print("d=",d)</pre>
思路

&nbsp;

把n看作a+c,那么n**e mod c=a**e mod c，这一步就是二项式定理，展开之后后的项一定会有c，那么mod c时就会直接约去，这个时候直接去算a的大小，n就出来了

&nbsp;

exp
<pre class="code">c=
hint=
e=
d=

from Crypto.Util.number import *
phic=euler_phi(c)

dc=inverse_mod(e,phic)
a=pow(hint,dc,c)
n=int(a)+int(c)
m=power_mod(c,d,n)
print(long_to_bytes(m))</pre>
&nbsp;

&nbsp;
<h3>简单密码</h3>
task
<pre class="code">647669776d757e83817372816e707479707c888789757c92788d84838b878d9d</pre>
思路

&nbsp;

第一眼看上去像是16进制的东西，想着直接转换，没有出来，然后看了看ctfshow这个前缀，发现
<pre class="code">ctfshow（hex一下）
63 74 66 73 68 6f 77
64 76 69 77 6d 75 7e 83817372816e707479707c888789757c92788d84838b878d9d</pre>
这个规律就出来了

&nbsp;

&nbsp;

exp
<pre class="code">a=0x647669776d757e83817372816e707479707c888789757c92788d84838b878d9d

from Crypto.Util.number import*

cnt=1
for i in long_to_bytes(a):
   print(chr(i-cnt),end='')
   cnt=cnt+1</pre>
&nbsp;

&nbsp;
<h3>混合密码体系</h3>
&nbsp;

task
<pre class="code">from Crypto.Util.number import bytes_to_long,getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 对称加密
flag = b'ctfshow{***}' # 密文，隐藏
key = b'flag{***}' # 会话密钥，隐藏
iv = b'flag{1fake_flag}' # AES偏移向量，已知
# 对明文进行填充，使其长度符合AES加密的要求
padded_plaintext = pad(flag, AES.block_size)

# 创建AES加密对象
cipher = AES.new(key, AES.MODE_CBC, iv)

# 加密
ciphertext = cipher.encrypt(padded_plaintext)

# 加密后的文本通常是字节串，转成整数便于进行会话密钥的RSA加密
c1 = bytes_to_long(ciphertext)

print(f'c1 = {c1}')

# 非对称加密
m = bytes_to_long(key)
e = 0x10001
p = getPrime(1024)
q = getPrime(1024)
n = p * q
c = pow(m,e,n)
print(f'p = {p}')
print(f'q = {q}')
print(f'n = {n}')
print(f'c2 = {c}')
# print("hint:key需要转成字节流也就是b''")</pre>
思路

&nbsp;

字多，但是不难，先把key算出来，iv偏移量已知，那么全都出来了

&nbsp;

exp
<pre class="code">c1=
c2=
p=
q=
n=
e=

from Crypto.Util.number import*

phi=(p-1)*(q-1)
d=inverse(e,phi)
key=pow(c2,d,n)

iv = b'flag{1fake_flag}'

from Crypto.Cipher import AES

cipher = AES.new(long_to_bytes(key), AES.MODE_CBC, iv)
plaintext = cipher.decrypt(long_to_bytes(c1))
print(plaintext)</pre>
