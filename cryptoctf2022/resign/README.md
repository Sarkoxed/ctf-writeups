---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.14.1
  kernelspec:
    display_name: Python 3 (ipykernel)
    language: python
    name: python3
---

<h>Task:</h>
<p>You can read resign.py in this repo to get an idea how the task works</p>

```python
from pwn import *
from Crypto.Util.number import bytes_to_long as b2l
from hashlib import sha1

import os
from sage.all import *
from gmpy2 import *
```

<p>Here's a simple wrapper to communicate with socket</p>

```python
def skip(p):
    p.recvuntil(b"[Q]uit")

def get_params(p):
    p.sendline(b"r")
    p.recvuntil(b"e =")
    e = int(p.recvline().decode())
    p.recvuntil(b"n =")
    n = int(p.recvline().decode())

    return n, e

def guess(con, e, p, q):
    con.sendline(b"g")
    print("sending")
    con.recvuntil(b"like e, p")
    print("received")
    con.recvline()
    print("received")
    con.sendline(f"{e}, {p}, {q}".encode())
    res = con.recvline().decode().strip()
    if "Great guess" not in res:
        print(f"[-] Something went wrong, server says: {res}")
    else:
        print("[+] Successfully forged parameters")

def get_signature(p):
    p.sendline(b"p")
    p.recvuntil(b"SIGN = ")
    signature = int(p.recvline().decode())
    return signature

def forge(conn, e, p, q):
    sig = b'Can you forge any signature?'
    phi = (p - 1)*(q-1)
    d = pow(e, -1, phi)
    h = b2l(sha1(sig).digest())
    sig = pow(int(h), int(d), int(p*q))
    conn.sendline(b"s")
    conn.recvuntil(b"this messag")
    conn.recvline()
    conn.recvline()
    conn.sendline(str(sig).encode())
```

<p>This code, which generates smooth primes I have borrowed from picoctf2022 task very_smooth</p>

```python
SEED  = mpz(os.urandom(32).hex(), 16)
STATE = random_state(SEED)

def get_prime(state, bits):
    return next_prime(mpz_urandomb(state, bits) | (1 << (bits - 1)))

def get_smooth_prime(state, bits, smoothness=16):
    p = mpz(2)
    p_factors = [p]
    while p.bit_length() < bits - 2 * smoothness:
        factor = get_prime(state, smoothness)
        p_factors.append(factor)
        p *= factor

    bitcnt = (bits - p.bit_length()) // 2

    while True:
        prime1 = get_prime(state, bitcnt)
        prime2 = get_prime(state, bitcnt)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() < bits:
            bitcnt += 1
            continue
        if tmpp.bit_length() > bits:
            bitcnt -= 1
            continue
        if is_prime(tmpp + 1):
            p_factors.append(prime1)
            p_factors.append(prime2)
            p = tmpp + 1
            break

    p_factors.sort()

    return (p, p_factors)
```

<!-- #region -->
<p>The idea is to create a valid key, because of this part of resign.py code:</p>
```python
try:
    E, P, Q = [int(_) for _ in PARAMS.split(',')]
    if P.bit_length() == Q.bit_length() == 1024 and P != Q:
        N = P * Q
        PHI = (P - 1) * (Q - 1)
        D = inverse(E, PHI)
        if pow(h, D, N) == SIGN:
            e, n, d = E, N, D
            pr(border, 'Great guess, now you are able to sign any message!!!')
```
<p>Which allows us to rewrite the parameters that are used on server</p>
<p>And we can do this by generating smooth primes and solving dlp for the signature we've been given, since it's always the seim:</p>
<code>MSG = b'::. Can you forge any signature? .::'</code>
<!-- #endregion -->

```python
def check(p, q, s, h):
    P = GF(p)
    Q = GF(q)
    try:                             # sometimes crt or dlp may fail
        d1 = discrete_log(P(s), P(h))
        d2 = discrete_log(Q(s), Q(h))
        d = crt([d1, d2], [p-1, q-1])
        e = pow(d, -1, (p-1)*(q-1))
        return True
    except:
        return False

def get_valid_key(signature):
    e = 0x10001
    h = 859134015240994359820678247621894875833976723365 # it's the default message

    while True:
        p, p_factors = get_smooth_prime(STATE, 1024, 16)
        if len(p_factors) != len(set(p_factors)):
            continue
            
        # Smoothness should be different or some might encounter issues.
        q, q_factors = get_smooth_prime(STATE, 1024, 17)
        if len(q_factors) != len(set(q_factors)):
            continue

        factors = p_factors + q_factors
        
        if(int(p) * int(q) < signature):        # check that n is greater than s, otherwise decryption will not succeed
            continue

        if(not check(p,q,signature,h)):
            continue
        if e not in factors:
            break

    P = GF(p)
    Q = GF(q)
    d1 = discrete_log(P(signature), P(h))
    d2 = discrete_log(Q(signature), Q(h))
    d = crt([d1, d2], [p-1, q-1])
    e = pow(d, -1, (p-1)*(q-1))
    return (e, p, q)
```

```python
p = remote("03.cr.yp.toc.tf", 11137)
skip(p)
print("getting params")
print(get_params(p))
skip(p)
print("getting sig")
sig = get_signature(p)
print(sig)
skip(p)
print("guessing")
e, p1, q = get_valid_key(sig)
guess(p, e, p1, q)
skip(p)
print("forging")
forge(p, e, p1, q)
while True:
    try:
        print(p.recvline())
    except:
        break
```
