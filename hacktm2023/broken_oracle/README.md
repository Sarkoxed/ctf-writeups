# HACKTM 2023
## broken_oracle

Attachments:

```python
#!/usr/local/bin/python3
"""
implementation of https://www.cs.umd.edu/~gasarch/TOPICS/miscrypto/rabinwithrecip.pdf
"""
import os
import random
from dataclasses import dataclass
from math import gcd
from typing import List, Tuple

import gmpy2
from Crypto.Util.number import bytes_to_long, getPrime

from secret import flag


@dataclass
class Pubkey:
    n: int
    c: int


@dataclass
class Privkey:
    p: int
    q: int


@dataclass
class Enc:
    r: int
    s: int
    t: int

    def __repr__(self) -> str:
        return f"r = {self.r}\ns = {self.s}\nt = {self.t}"


def crt(r1: int, n1: int, r2: int, n2: int) -> int:
    g, x, y = gmpy2.gcdext(n1, n2)
    assert g == 1
    return int((n1 * x * r2 + n2 * y * r1) % (n1 * n2))


def gen_prime(pbits: int) -> int:
    p = getPrime(pbits)
    while True:
        if p % 4 == 3:
            return p
        p = getPrime(pbits)


def genkey(pbits: int) -> Tuple[Pubkey, Privkey]:
    p, q = gen_prime(pbits), gen_prime(pbits)
    n = p * q
    c = random.randint(0, n - 1)
    while True:
        if gmpy2.jacobi(c, p) == -1 and gmpy2.jacobi(c, q) == -1:
            break
        c = random.randint(0, n - 1)
    pubkey = Pubkey(n=n, c=c)
    privkey = Privkey(p=p, q=q)
    return pubkey, privkey


def encrypt(m: int, pub: Pubkey) -> Enc:
    assert 0 < m < pub.n
    assert gcd(m, pub.n) == 1
    r = int((m + pub.c * pow(m, -1, pub.n)) % pub.n)
    s = int(gmpy2.jacobi(m, pub.n))
    t = int(pub.c * pow(m, -1, pub.n) % pub.n < m)
    enc = Enc(r=r, s=s, t=t)
    assert s in [1, -1]
    assert t in [0, 1]
    return enc


def solve_quad(r: int, c: int, p: int) -> Tuple[int, int]:
    """
    Solve x^2 - r * x + c = 0 mod p
    See chapter 5.
    """

    def mod(poly: List[int]) -> None:
        """
        Calculate mod x^2 - r * x + c (inplace)
        """
        assert len(poly) == 3
        if poly[2] == 0:
            return
        poly[1] += poly[2] * r
        poly[1] %= p
        poly[0] -= poly[2] * c
        poly[0] %= p
        poly[2] = 0

    def prod(poly1: List[int], poly2: List[int]) -> List[int]:
        """
        Calculate poly1 * poly2 mod x^2 - r * x + c
        """
        assert len(poly1) == 3 and len(poly2) == 3
        assert poly1[2] == 0 and poly2[2] == 0
        res = [
            poly1[0] * poly2[0] % p,
            (poly1[1] * poly2[0] + poly1[0] * poly2[1]) % p,
            poly1[1] * poly2[1] % p,
        ]
        mod(res)
        assert res[2] == 0
        return res

    # calculate x^exp mod (x^2 - r * x + c) in GF(p)
    exp = (p - 1) // 2
    res_poly = [1, 0, 0]  # = 1
    cur_poly = [0, 1, 0]  # = x
    while True:
        if exp % 2 == 1:
            res_poly = prod(res_poly, cur_poly)
        exp //= 2
        if exp == 0:
            break
        cur_poly = prod(cur_poly, cur_poly)

    # I think the last equation in chapter 5 should be x^{(p-1)/2}-1 mod (x^2 - Ex + c)
    # (This change is not related to vulnerability as far as I know)
    a1 = -(res_poly[0] - 1) * pow(res_poly[1], -1, p) % p
    a2 = (r - a1) % p
    return a1, a2


def decrypt(enc: Enc, pub: Pubkey, priv: Privkey) -> int:
    assert 0 <= enc.r < pub.n
    assert enc.s in [1, -1]
    assert enc.t in [0, 1]
    mps = solve_quad(enc.r, pub.c, priv.p)
    mqs = solve_quad(enc.r, pub.c, priv.q)
    ms = []
    for mp in mps:
        for mq in mqs:
            m = crt(mp, priv.p, mq, priv.q)
            if gmpy2.jacobi(m, pub.n) == enc.s:
                ms.append(m)
    assert len(ms) == 2
    m1, m2 = ms
    if m1 < m2:
        m1, m2 = m2, m1
    if enc.t == 1:
        m = m1
    elif enc.t == 0:
        m = m2
    else:
        raise ValueError
    return m


if __name__ == "__main__":
    pbits = 1024
    pub, priv = genkey(pbits)
    while len(flag) < 255:
        flag += os.urandom(1)
    enc_flag = encrypt(bytes_to_long(flag), pub)
    print("encrypted flag:")
    print(enc_flag)
    while True:
        try:
            r, s, t = map(int, input("r, s, t = ").split(","))
            enc = Enc(r=r, s=s, t=t)
            enc_dec_enc = encrypt(decrypt(enc, pub, priv), pub)
            print("decrypt(encrypt(input)):")
            print(enc_dec_enc)
        except Exception:
            print("Something wrong...")
```

This was a task on a cryptosystem that is mentioned at the top of this very long page.
It's build on the top of Rabin cryptosystem. It's not so hard to understand the main idea. 

We are given the public parameters(<b>We are not given but they are still public)</b>) $c$ and $n$. 
$c$ is a quadratic non-residue mod $n$. $p$ and $q$ are specifically chosen to not have square roots of -1 in their subfields. 

The encryption goes like this: 
1) $m \in [0, n]$
2) $r = m + cm^{-1}\ mod(\ n)$
3) $s = (\frac{m}{p})(\frac{m}{q})$ (Legendre symbol)
4) $t = (c m^{-1}) mod(\ n) < m$ (bool)

The last two flags are needed for proper decryption. 
The decryption consists of solving a quadratic equation $x^2 - r x + c$ modulo composite n, which is only possible for puny humans if they know factorization of n.

The first thing to notice is the implementation of this process. The function solve_quad simply takes the remainder of $x^{\frac{p - 1}{q}} - 1$ modulo $x^2 - r x + c$. 
If the solution exists then this algorithm finds it. The quotient will be in form $a * x + b\ (mod\ p)$ and $x$ can be found by usual methods. $x = - b a^{-1}\ mod(\ p)$. The same process goes modulo $q$ and then CRT goes brrrr.

However, what if there're no solutions of this quadratic equation modulo $p$? Then it finds the quotient and performs the similar operations on $a$ and $b$ like above. It will not be anything but garbage. Which helps us to attack it. 


We are given an oracle, which asks us for triples $r, s, t$. It'll decrypt $r$ and then encrypt it again. Imagine if we send correct triple. The oracle will return the same result as we sent him.
There're also some checks for flags during encryption but it's not so important. 

Consider the case when there're no solutions to both equations:
$x^2 - r x + c = 0\ mod(\ p)$

$x^2 - r x + c = 0\ mod(\ q)$

the result will be some useless garbage. 
However if the one of them had solutions then we have an interesting result:
Let's assume that there're solutions modulo $q$. 

The algorithm will return the valid solution modulo $q$ and some garbage modulo $p$. After that the final solutions is found by $X = crt([x_p, x_q], [p, q])$. And it will definetely not be our $r$ that we have sent. 

Switching the flag $s$ to the opposite  value will force the oracle to use another root $r - x_p$ which will result in yet another return value. Notice that since there're solutions mod $q$, there only two possible return values(4 if both equations have no solutions).

# HERE WE HAVE

$x^2 - r x + c = 0\ mod(\ q)$

$x^2 - r_1 x + c = 0\ mod(\ q)$

$x^2 - r_2 x + c = 0\ mod(\ q)$

Let's look at them in pairs

$x^2 - r x + c - x^2 + r_1 x - c = x(r_1 - r) = 0\ (mod\ q)$

$x^2 - r x + c - x^2 + r_2 x - c = x(r_2 - r) = 0\ (mod\ q)$

Since $x$ is definetely not equal 0 mod $q$ we have two positive integers $r_1 - r$ and $r_2 - r$ whose non-trivial factor is $q$. We doesn't even need $n$ to factor $q$. Hoever it have to take several rounds since there'll be another non trivial factors of these integers. Thanks to randomness it won't be a big problem.

Also all this applies to $p$ too. We just need to wait a bit.

We also could use the timing attack to find n with binary search but it was too long for me.

<b>By the time</b> we will need $r, r_1, r_2$ further so we can keep them.


```python
from pwn import remote
from random import randint, choice
from Crypto.Util.number import long_to_bytes
```


```python
def parse_flag(r):
    r.recvuntil(b"r = ")
    flag = eval(r.recvline().decode())
    r.recvuntil(b"s = ")
    s = eval(r.recvline().decode())
    r.recvuntil(b"t = ")
    t = eval(r.recvline().decode())
    return (flag, s, t)


def send_params(r, R, s, t):
    f = r.recvuntil(b"= ")
    r.sendline(f"{R}, {s}, {t}".encode())
    data = r.recvline().decode()
    if "decrypt" in data:
        R1 = int(r.recvline().decode()[3:].strip())
        s1 = int(r.recvline().decode()[3:].strip())
        t1 = int(r.recvline().decode()[3:].strip())
        return data, (R1, s1, t1)
    return data, (-1, -1, -1)


def send_random_params(r, B):
    R = randint(0, B)
    s = choice([-1, 1])
    t = choice([0, 1])
    data, ret = send_params(r, R, s, t)
    if ret[0] != R:                     # check for no solutions
        return True, ret, R
    return False, None, None
```

Here comes the main attack


```python
def recover_n(r, B):
    samples1 = (0, 0)         # samples to factor q
    samples2 = (0, 0)         # samples to factor p
    
    while True:
        if len(samples2) * len(samples1) > 0 and is_prime(samples1[0]) and is_prime(samples2[0]):
            if samples1[0] == samples2[0]:
                return None
            break
        
        flag, ret, R = send_random_params(r, B)  # flag indicates that the return value differs
        if flag:
            print("here")
              
            rs = set()
            for s, t in ((-1, 1), (-1, 0), (1, 1), (1, 0)):
                data, ret = send_params(r, R, s, t)
                rs.add(ret[0])
            
            rs = list(rs)
            if len(rs) == 2:                
                tmp = gcd(R - rs[0], R - rs[1])
                
                if samples1[0] == 0 and samples2[0] == 0:
                    samples1 = (tmp, rs, R)
                    print("initiated samples for q")
                    continue       
                    
                tmp1 = gcd(tmp, samples1[0])    # gcd all over again
                if tmp1 > 2**1022:
                    samples1 = (tmp1, rs, R)
                    #print(samples1)
                    continue
                
                if samples2[0] == 0:
                    samples2 = (tmp, rs, R)
                    print("initiated samples for p")
                    continue
                
                tmp2 = gcd(tmp, samples2[0])    # and again
                if tmp2 > 2**1022:
                    samples2 = (tmp2, rs, R)   
                    #print(samples2)
    return samples1, samples2  
```


```python
r = remote("34.141.16.87", int(50001))
rf, sf, tf = parse_flag(r)
    
while True:
    samples = recover_n(r, 100000000) # it doesn't really matter but by hand it worked, so...
    if samples is not None:
        break
r.close()
q = samples[0][0]
p = samples[1][0]
n = p * q
   
print("Found n, p, q")
n, p, q
```

    [x] Opening connection to 34.141.16.87 on port 50001
    [x] Opening connection to 34.141.16.87 on port 50001: Trying 34.141.16.87
    [+] Opening connection to 34.141.16.87 on port 50001: Done
    here
    initiated samples for q
    here
    initiated samples for p
    [*] Closed connection to 34.141.16.87 port 50001
    Found n, p, q





    (14168635699413242888537453025992633467008872922806369412435935664804461815458652081037826157790338194441129824597621295144565677430770066927135855614607015762552869040181925963019245086850194791865316929300943998584073399631840174442986555418712535977177313791251621179360460950042798577182343977810629803296118467356213448596231239312303342577471682789748843215766769341474391214374567280190322825302710832480580946988557152104168092394602712903051070363107594363104464732970389177688551158609305391972745446445641860174900939382523325186186129292590730989678623626911886508228856611817342347099776211655381906625037,
     106741120663336542097576383139284649010402687356304252599504230795259119453582939500316381973764496169344286074571628286488613799235763471636676637903215644092154157422505977404393912474802440642406805263034538324748000286718246013435699546550836173307670099360045148985600610462665936573031977191349995745003,
     132738307517881327980644439606021855370934064342381387993446140216529230485665793213023632114655105692320153321297902316105537250794707441690782938898288059801620825262442115035703163201362336306410129058843899127399646305698192846125405912868409144064405021888516427713118091315221763137870582383733025256679)



Last problem. We do not know c. 

But we know that there's a value modulo $p$($q$) such that in the first equation it's $l_p$ and in the second it's $r - l_p$.

$l_p^2 - r_1 * l_p + c = 0\ mod(\ p)$

$(r - l_p)^2 - r_2 * (r - l_p) + c = 0\ mod(\ p)$

substracting them and expanding the squares we have a linear equation in $l_p$:

$l_p * (r_1 + r_2 - 2 R) = r_2 R - R^2\ (mod\ p)$

Hence we got $c_p = r_1 l_p - l_p^2\ mod(\ p)$

Еhe same way we find $c_q$ and finally get $c = crt([c_p, c_q], [p, q])$


```python
r1, r2 = samples[0][1]
R = samples[0][2]
assert gcd(r1 - R, q) == q
   
lp = ((r2 * R - R**2) * pow(-2*R + r1 + r2, -1, p)) % p
cp = (r1 * lp - lp**2) % p
```


```python
r1, r2 = samples[1][1]
R = samples[1][2]
assert gcd(r1 - R, p) == p

lq = ((r2 * R - R**2) * pow(-2 * R + r1 + r2, -1, q)) % q
cq = (r1 * lq - lq**2) % q
```


```python
c = crt([int(cp), int(cq)], [p, q])
c
```




    8209161946209095044898734070013204336981861428521739737049328866369608782681072961917695541542993841567171813442106101243927303282520063912679034430772853666197355115878939248229758620947033398263345800778684548314746423378165136703228808937267758838025759060296604928038130102411399149377672011386617240162109513256034359145620292066465743331695931464907935652426297359086355191340983349435293192687513276698200562637581171769247902088374908572682716217829785118035096487105753845215503785668613342285503833129604591669582641576834049828121027236249374120284190405448966544326234430076621295281886401785277019462057



Then we just follow the decryption. I wanted to sleep.


```python
x = var('x')
rp = PolynomialRing(GF(p), x)(x**2 - rf * x + c).roots()
rq = PolynomialRing(GF(q), x)(x**2 - rf * x + c).roots()

for r1, _ in rp:
    for r2, _ in rq:
        root = crt([int(r1), int(r2)], [p, q])
        m = long_to_bytes(int(root))
        if b'HackTM' in m:
            print(m)
```

    b'HackTM{h4v3_y0u_r34lly_f0und_4ll_7h3_bu65...?}\x1dL^T=\xf3\xdb0hZ\xc5wX\x1e\x18\xa6\xf0\xf5\xd8\xdaE\xc4;\x1d%\x11\xd8\x05J\x9a+\xce\x1b*\x81\xe9\x8bi\xcb\xc8"\xc2$\x1e\x1d\x92\xa28\x1bM\x04\xc8j\xbfh}A$\x19\x1f#k\xd8\xdd_\xed r\xb7I\xd1/\xd6t\x80!\x90Wt\xd2 \xb8\xd5\xba8b3\xe8,Jy\xdaT\xd9\xb3\x8a\xf8\x87\xd5\xb3\xc7\x86\x03\xef\x14w\xd4\xaa\x15\tSNVou\xb1\x81\xd5\x95[\xe7],\x9c-/\xe6\x91\xe4|\x80\xb5\x96\xcd&\x86\x13\x88e\xae\xef\xdcS\x89\x17\x17\xe7Z\x7fQ\xd7C\x0bp/\xc9b\xcb\xca?\x9c[<\x889\x8c[\x8a\x06\xe2\x06\xc00Q\xb1xZ\xe0\xdc\x9f\xbc\xe9\xf8\xaf7J\xbeF\x03D\x13\xa11cr\xe8\xf1\xe629\'\xde\xbdO\x8d!u\xbd\xce'

