# DiceCTF 2023

## BBBB

Task description:
<pre>i prefer LCGs over QCGs to be honest...

based off BBB from SECCON CTF 2022

nc mc.ax 31340</pre>
### Attachments:
```python
from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from math import gcd
from os import urandom

def generate_key(rng, seed):
    e = rng(seed)
    while True:
        for _ in range(randint(10,100)):
            e = rng(e)
        p = getPrime(1024)
        q = getPrime(1024)
        phi = (p-1)*(q-1)
        if gcd(e, phi) == 1:
            break

    n = p*q
    return (n, e)

def generate_params():
    p = getPrime(1024)
    b = randint(0, p-1)

    return (p,b)

def main():
    p,b = generate_params()
    print("[+] The parameters of RNG:")
    print(f"{b=}")
    print(f"{p=}")
    a = int(input("[+] Inject b[a]ckdoor!!: "))
    rng = lambda x: (a*x + b) % p

    keys = []
    seeds = []
    for i in range(5):
        seed = int(input("[+] Please input seed: "))
        seed %= p
        if seed in seeds:
            print("[!] Same seeds are not allowed!!")
            exit()
        seeds.append(seed)
        n, e = generate_key(rng, seed)
        if e <= 10:
            print("[!] `e` is so small!!")
            exit()

        keys.append((n,e))

    FLAG = open("flag.txt", "rb").read()
    assert len(FLAG) < 50
    FLAG = FLAG + urandom(4)

    for n,e in keys:
        r = urandom(16)
        flag = bytes_to_long(FLAG + r)
        c = pow(flag, e, n)
        r = r.hex()
        print("[+] Public Key:")
        print(f"{n=}")
        print(f"{e=}")
        print(f"{r=}")
        print("[+] Cipher Text:", c)
        
        
if __name__ == "__main__":
    main()
```

This task asks us to send it one of LCG parameters, where 
LCG is simply the Linear Recurrence Relation, which holds over some prime number.
$x_n = a * x_{n-1} + b\ (mod\ p)$

Since there's a constant $b$ it's not quite a requrrence relation, however we can get rid of it by:
$x_n = a * x_{n-1} + b\ (mod\ p)$
$x_{n-1} = a * x_{n-2} + b\ (mod\ p)$
$x_n = (a + 1) * x_{n-1} + a * x_{n-2}\ (mod\ p)$

This relation has it's characteristic polynomial $x^2 - (a+1) * x - a$, which has roots $a$ and $1$, hence the general solution will be $x_n = C_1 * a^n + C_2$ if $a \ne 1$ and $x_n = C_1 * n + C_2$ otherwise.

Since we are working in the finite field we actually can use the first case to make the recurrence cyclic. The key idea is to choose $a$ which has a small multiplicative order. My idea was to find an $a$ with order 5(since there's a restriction on amount of distinct seeds) and the first element is 11(since it's the lowest possible exponent to use). Also the final property of $a$ should be that all the elements in this 5 element sequence would be even, exept for 11, because this will lead to using 11 every time when <b>generate_key</b> function is called, which is quite comfortable.

The last step is breaking rsa with exponent 11 and known padding.
Due to Coppersmith and Hastad we can perform an attack, which uses the fact that secret message $m$ is always a root of some polynomial modulo $N$ with degree $d$ (11 in our case). 

After sending $a$ and $seeds$ we have 5 ciphertexts, modules, exponents and paddings

$c_1 = (2^{16 * 8} * M' + r_1)^{11}\ (mod\ N_1)$

$c_2 = (2^{16 * 8} * M' + r_2)^{11}\ (mod\ N_2)$

$c_3 = (2^{16 * 8} * M' + r_3)^{11}\ (mod\ N_3)$

$c_4 = (2^{16 * 8} * M' + r_4)^{11}\ (mod\ N_4)$

$c_5 = (2^{16 * 8} * M' + r_5)^{11}\ (mod\ N_5)$


Then we calculate $g_i(x) = (2^{16 * 8} * x + r_i)^{11} - c_i) * 2^{- 16 * 8}(\ (mod\ N_i)$ to make it monic and finally $g(x) = T_1 * g_1(x) + T_2 * g_2(x) + T_3 * g_3(x) + T_4 * g_4(x) + T_5 * g_5(x)\ (mod\ N_1 * N_2 * N_3 * N_4 * N_5)$, where $T_i = 1\ (mod\ N_i)$ and $T_i = 0\ (mod\ N_j), j\ne i$ 

We know that $g(M') = 0\ (mod\ N_1 * N_2 * N_3 * N_4 * N_5)$ and that $M'$ is quite small, so we can apply Coppersmith method to find small roots of a polynomial modulo.


```python
import re
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import context, remote
from sage.all import PolynomialRing, Zmod, crt, product, randint, var
```


```python
context.log_level = "error"
```


```python
def lrs(p, a, b, x0, n):       # calculate x_n
    for i in range(n):
        x0 = (a * x0 + b) % p
    return x0
```


```python
def get_ass(p):
    if (p - 1) % 5 != 0:       # (p - 1) should be devisible by 5 to make an element with order 5 exist.
        return None

    while True:
        a = pow(randint(1, p - 1), (p - 1) // 5, p)
        if a != 1:
            break
    ass = [pow(a, i, p) for i in range(5)]
    return ass[1:]
```


```python
def get_a(ass, p, b, e):
    for k in range(4):
        tmp = []
        for i in range(5):
            tmp.append(int(lrs(p, ass[k], b, 11, i)) % 2)       # finding such an a so all the elements are even except for 11
        if not any(tmp[1:]):
            return ass[k]
    return None
```


```python
host, port = "mc.ax", 31340
#host, port = "localhost", 17778
trie = 1
```


```python
while True:
    print(f"try ${trie}")
    trie += 1

    r = remote(host, port)
    r.recvline()
    bs = r.recvline().decode()
    b = int(re.findall(r"b=(.*)\n", bs)[0])

    ps = r.recvline().decode()
    p = int(re.findall(r"p=(.*)\n", ps)[0])

    ass = get_ass(p)
    if ass is None:
        r.close()
        continue
    print("found ass")

    a = get_a(ass, p, b, 11)
    if a is None:
        r.close()
        continue
    print("found a!")
    r.sendline(str(a).encode())
    r.recvuntil(b"door!!:")
    break
```

    try $1
    try $2
    try $3
    try $4
    try $5
    try $6
    try $7
    found ass
    try $8
    found ass
    try $9
    try $10
    try $11
    try $12
    found ass
    try $13
    found ass
    try $14
    try $15
    found ass
    found a!



```python
for i in range(5):
    print(f"seed {i}")
    r.sendline(str(lrs(p, a, b, 11, i)).encode())
    r.recvuntil(b"input seed:")
```

    seed 0
    seed 1
    seed 2
    seed 3
    seed 4



```python
ns, cs, es, rs = [], [], [], []
for i in range(5):
    r.recvuntil(b"Public Key:\n")

    nst = r.recvline().decode()
    n = int(re.findall(r"n=(.*)\n", nst)[0])
    ns.append(n)

    est = r.recvline().decode()
    e = int(re.findall(r"e=(.*)\n", est)[0])
    print(e)
    es.append(e)

    rst = r.recvline().decode()
    rr = int(re.findall(r"r='(.*)'\n", rst)[0], 16)
    rs.append(rr)

    r.recvuntil(b"Cipher Text: ")
    cst = r.recvline().decode()
    c = int(re.findall(r"(.*)\n", cst)[0])
    cs.append(c)
r.close()
```

    11
    11
    11
    11
    11



```python
def coppersmith(ns, cs, rs, e):
    x = var("x")
    g = 0
    gs = []
    for i in range(5):
        n = ns[i]
        c = cs[i]
        r = rs[i]
        ring = PolynomialRing(Zmod(n), x)
        gi = ring((2 ** (16 * 8) * x + int(r)) ** e - int(c)).monic()
        Ti = crt([0 if i != j else 1 for j in range(5)], ns)
        g += Ti * gi.change_ring(Zmod(product(ns)))
        gs.append(gi)
    return g, gs
```


```python
g, gs = coppersmith(ns, cs, rs, e)
flag = g.small_roots(X=2 ** (54 * 8), beta=0.4)[0]
print(long_to_bytes(int(flag)))
```

    b'dice{r3s0rt_t0_LCG_4ft3r_f41l1ng_t0_m4k3_ch4ll}xR\x07\xe2'

