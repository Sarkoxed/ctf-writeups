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

# Disinvolute
Note: Solution is unintended

## Description
<pre>
Cryptosystem that I have developed uses a set of procedures known as cryptographic disinvolute algorithms.

nc 65.21.255.31 12431
nc 188.34.203.80 12431

</pre>
<b>No attachments</b><br>
Output from socket:
<pre>
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|  Welcome to disinvolute challenge, with respet you should solve a    |
|  very hard nested DLP problem! For this I have used safe primes to   |
|  insure that secuirty is MAX! This is an impossible mission! YES!!!  |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Options:
|       [E]ncrypted flag!
|       [F]acts
|       [Q]uit
F
| e = 65537
| g = 19
| G = 7
| n = 126817219028606140440909929555626882017032868581677730360289090645417210565865712959055686403299389411320234628860402488799212584899944351871118800624694008941834723226969169304172676271632933365480328377235593062516957219629026796125251528168478419843686003229828708071527939921707413604946466960801416034117
| x = 363259061254929246635815086309583926479751985388773318959515609623341060489308455953298274795462268009063514873410428823408419180662329709306384633116099239551636218622667816820069700044443018167845353859055658694736850591237009656106990800528300148707604972664409367653277774390670183187440780500307179239
| y = 147891519347056175221533178934842161441006012995134619812533387291657853343797157298018501535376517192385607546849551161454575414353106307375951727161784643842405400941599100105707074104304764857011931092110265070500732647855323321204444123238533303610283566373180808121400613219793765794398764590913417058589559
| m = bytes_to_long(flag)
| pow(g, pow(G, x), n) == pow(g, pow(G, y), n)
| Options:
|       [E]ncrypted flag!
|       [F]acts
|       [Q]uit
E
| pow(m, e, n) = 94635799754849737996179438897316661904096199960423902626561026359597490424651317212764011026988643862869806426528293181566478952934320109504067886143847768757668982865986219018245239540959961962445319610775905082069434896523194702877016305523646928667555806384730664597586240946082861560916829078697893564128
| Options:
|       [E]ncrypted flag!
|       [F]acts
|       [Q]uit
Q
| Quitting ...

</pre>

## Solution
It was a hard one, which I almost guessed(I think??). So I've been analysing the primes from the output for 5 hours(from the corresponding phi's) and I was almost sure that they are probably strong(of the form ```1 + 2 * p``` where p is prime).<br>
The next observation was about this equation: ```pow(g, pow(G, x), n) == pow(g, pow(G, y), n)```<br>
Well, we have a situtation... or are we?<br>
```g^(G^x) = g^(G^y) (mod n)```<br>
```G^x = G^y (mod phi(n))```<br>
```x = y (mod phi(phi(n)))```<br>
Well, not almost true, but at least it happens. There maybe a situtation when ```x = y (mod phi(phi(n)) / ord(G)```, or ```G^x = G^y (mod phi(n) / ord(g))``` but... Let's hope for the best!<br>
For <b>strong</b> primes I have figured out a formula:<br>
Lets ```p = 1 + 2 * r, q = 1 + 2 * t```, hence ```phi(n) = 2 * r * t``` and ```phi(phi(n)) = 2 * (r - 1) * (t - 1) = 2 * t * r - 2 * (t + r) + 2```<br>
strange. Where could we find ```phi(phi(n))```?
Let's look at ```x = y (mod phi(phi(n)))```, here's the answer: ```y - x = K * phi(phi(n))```(also we know that phi(phi(n)) has a pretty close order to the order of n so, since ```y-x``` is a <b>bit</b> bigger than n we can be sure that small factors that we will figure out might be that K.(I know it because  <b><i>I was staring into this numbers for too long, so the numbers started to stare back at me...</i></b>)

```sage
from pwn import remote
from factordb.factordb import FactorDB
import re
from time import sleep
```

```sage
def get_num(x):
    return re.findall(r'[\d]+', x)[0]

def get_params(host, port):
    r = remote(host, port)
    r.sendline(b"F")
    r.sendline(b"E")
    r.sendline(b"Q")

    for i in range(10):
        r.recvline()
    tmp = [r.recvline().decode() for _ in range(5)]
    g, G, n, x, y = [int(get_num(x)) for x in tmp]
    
    for i in range(6):
        r.recvline()

    tmp = r.recvline().decode()
    c = get_num(tmp)

    r.close()
    q = FactorDB(abs(int(x)-int(y)))
    q.connect()
    sleep(10)
    return g, G, x, y, n, 2**16+1, c
```

```sage
def get_phiphis(x, y, n):
    d = abs(x - y)
    
    q = FactorDB(d)
    q.connect()
    l = q.get_factor_list()

    prob_phiphis = []
    for num in range(1, len(l)+1):
        for comb in combinations(l, num):   # every divisor, combined of small factors
            d1 = d // product(comb)
            tmp = int(n).bit_length() - int(d1).bit_length()  # that's what I was talking about. We slightly correct d's
            if tmp >= 0 and tmp <= 4:            
                prob_phiphis.append(d1)
                
    prob_phiphis = list(set(prob_phiphis))
    prob_phiphis.append(d)
    return prob_phiphis
```

```sage
host, port = "65.21.255.31", 12431

from itertools import combinations
from Crypto.Util.number import long_to_bytes

r = 0
flag = False
while True:
    print(f"Try № {r + 1}")
    r += 1
    
    g, G, x, y, n, e, c = get_params(host, port)
    prob_phiphis = get_phiphis(x, y, n)


    for ph in prob_phiphis:
        t = n - 2 * ph + 9
        if t % 3 != 0 or t < 0:
            continue
        su = t // 3
        var('x')
        s = x**2 - su * x + n
        k = s.roots()
        if k[0][0].is_integer():
            p, q = k
            flag = True
            break
    if flag:
        break
print("WIN")
```

```sage
p = p[0]
q = q[0]
assert p * q == n
```

```sage
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, d, n)
long_to_bytes(m)
```
