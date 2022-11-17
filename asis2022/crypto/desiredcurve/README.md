---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.14.1
  kernelspec:
    display_name: SageMath 9.7
    language: sage
    name: sagemath
---

# Desired curve
Note: Solution is unintended

## Description
<pre>You can use a known curve to build a curve with the desired properties.

nc 65.21.255.31 10101</pre>
<b>Attachments in repo</b>

## Solution
The key to my solution is that:<br>
You have a point <code>Gf = flag * G</code>, and since you are able to factor the order of the point <code>G</code>(or at least find it's small factors), then you are able to solve ECDLP modulo this small factors(so you find <code>flag(mod smth)</code>, and after all use <code>CRT</code> to recover the flag.

```sage
from pwn import remote
```

```sage
def round(r, mods, rems):
    for i in range(6):
        r.recvline()
        
    y1, y2 = 1, 2
    r.sendline(b"1, 2")
    r.recvline()
    mes = r.recvline()
#   print(mes)
    mes = mes.decode().strip("|").strip().strip("q").strip().strip("=")  # I really wanted to sleep
    q = int(mes)

    g = GF(q)
    x1, x2 = 1337, 31137
    mes = r.recvline()
#    print(mes)
    mes = mes.decode().strip().strip("|").strip().strip("G").strip().strip("=")
    G1 = eval(mes)
    mes = r.recvline()
#    print(mes)
    mes = mes.decode().strip("|").strip().strip("m").strip().strip("*").strip().strip("G").strip().strip("=") # You know REALLY
    G2 = eval(mes)
    
    r.close()
    
    A = (y1**2 - y2**2 - 1337**3 + 31337**3) * pow(-30000, -1, q) % q
    B = (y1**2 - 1337**3 - A * 1337) % q

    E = EllipticCurve(g, [A, B])
    g1 = E(G1)
    g2 = E(G2)

    order = g1.order()
    print(order)
    
    factors = [x for x in prime_range(2, 2**20) if order % x == 0]
    print(factors)
    
    for mod in factors:
        if mod in mods:
            continue
        g = g1 * (order//mod)
        q = g2 * (order//mod)
      
        dl = discrete_log(q, g, operation="+")
        mods.append(mod)
        rems.append(dl)
```

```sage
host, port =  "65.21.255.31", 10101

mods, rems = [], []
n = 0
while product(mods) < 2**256:   # approximate value of flag
    print(f"Round: {n}")
    r = remote(host, port)
    round(r, mods, rems)
    print(f"Current mods: {mods}")
    print(f"Current rems: {rems}")
    print("_"*50)
    n += 1
    
flag = crt(rems, mods)
```

```sage
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(flag))
```
