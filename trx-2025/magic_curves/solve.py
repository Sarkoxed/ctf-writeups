from sage.all import EllipticCurve, GF, discrete_log, crt
from tqdm import tqdm
from Crypto.Util.number import getPrime
import multiprocessing as mp
from pwn import remote
import re
from math import isqrt

# I'm looking for the curve such that the following two curves are isomorphic:
# y^2 = x^3 + A * x + B
# y^2 = x^3 + B * x + A
# The one way I found is the affine transform: let x = lambda * x'
# y^2 = lambda^3 * x'^3 + B * lambda * x + A
# y^2 / lambda^3 = x'^3 + B / lambda^2 * x + A / lambda^3

# A = B / lambda^2
# B = A / lambda^3
# lambda^5 = 1 => we need a field with the 5th root of unity. It will also 
# be a square so we are not bothered with twists etc

# now we just need the order of the curve to be smooth enoutgh
# took me 2 minutes to find the good one
def find_curve(a):
    while True:
        p = getPrime(216)
        if (p - 1) % 5 == 0:
            break
    G = GF(p)
    lam = G(1).nth_root(5)
    for i in range(1000):
        a = G.random_element()
        b = a / lam**3
        e = EllipticCurve(G, [a, b])
        if all(x < 2**40 for x, _ in e.order().factor()):
            print(p, a, b)

with mp.Pool(22) as p:
    p.map(find_curve, range(1000))

p, a, b = 67473994618623484133601351626453276665262025024910550739556388641, 37414339222884117764857590660504682676224069820422649491070230218, 33248710592392548835992360227196286710036898510320720873697766698

e1 = EllipticCurve(GF(p), [a, b])
e2 = EllipticCurve(GF(p), [b, a])
# 2 * 3 * 23 * 2053 * 480839 * 1040749 * 10379449 * 1619239241 * 3772455913 * 34179915859 * 219604996529

print(e1.order() == e2.order())
print(e1.order().factor())

host, port = "magiccurves.ctf.theromanxpl0.it", 7005
r = remote(host, port)
r.sendline(f"{a}, {b}, {p}".encode())

m = r.recvline().decode()
P1, Q1, P2, Q2 = re.findall(r'\(\d* : \d* : 1\)', m)

P1 = e1([int(x) for x in re.findall(r'\d+', P1)][:-1])
Q1 = e1([int(x) for x in re.findall(r'\d+', Q1)][:-1])
P2 = e2([int(x) for x in re.findall(r'\d+', P2)][:-1])
Q2 = e2([int(x) for x in re.findall(r'\d+', Q2)][:-1])
print(e1.order().factor())
k1rems = []
k2rems = []
mods = []

# don't mind the bsgs function here
# I just like progress bars and discrete_log doesn't have them
def bsgs(G, Q, n=2**32):
    if n < 100:
        for i in range(100):
            if i * G == Q:
                return i
    m = isqrt(n) + 1
    
    pts = {}
    start = G
    for i in tqdm(range(1, m)):
        pts[start[0]] = i
        start += G

    R = m * G
    start = Q
    for j in tqdm(range(m)):
        if start[0] in pts:
            i = pts[start[0]]
            # i * P = Q - j * m * P
            if G * (i + j * m) == Q:
                return (i + j * m)
            else:
                assert G * (-i + j * m) == Q
                return (-i + j * m)
        start -= R

for q, _ in e1.order().factor():
    print(q)
    k1rems.append(bsgs( P1 * (P1.order() // q), Q1 * (e1.order() // q), q))
    k2rems.append(bsgs( P2 * (P2.order() // q), Q2 * (e2.order() // q), q))
    mods.append(q)

k1 = crt(k1rems, mods)
k2 = crt(k2rems, mods)
assert k1 * P1 == Q1
assert k2 * P2 == Q2
print(k1, k2)
r.sendline(f"{k1}, {k2}")
r.interactive()
