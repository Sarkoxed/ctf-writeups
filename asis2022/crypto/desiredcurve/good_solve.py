from sage.all import *
from factordb.factordb import FactorDB
from pwn import remote
from time import sleep

moduli = []
rems = []

def round(r):
    for i in range(6):
        r.recvline()
    y1, y2 = 1, 2
    r.sendline(b"1, 2")
    r.recvline()
    z = r.recvline()
    print(z)
    z = z.decode().strip("|").strip().strip("q").strip().strip("=")
    q = int(z)

    g = GF(q)
    x1, x2 = 1337, 31137
    z = r.recvline()
#    print(z)
    z = z.decode().strip().strip("|").strip().strip("G").strip().strip("=")
    g1 = eval(z)
    z = r.recvline()
#    print(z)
    z = z.decode().strip("|").strip().strip("m").strip().strip("*").strip().strip("G").strip().strip("=")
    g2 = eval(z)
    
    A = (y1**2 - y2**2 - 1337**3 + 31337**3) * pow(-30000, -1, q) % q
    B = (y1**2 - 1337**3 - A * 1337) % q

    E = EllipticCurve(g, [A, B])
    g1 = E(g1)
    g2 = E(g2)

    order = g1.order()
    print(order)
    facs = eval(input())
    for i in facs:
        print(i)
        mod=i
        if mod in moduli:
            continue
        _g_= g1 * (order//mod)
        _q_= g2 * (order//mod)
      
        dl=discrete_log(_q_,_g_,operation="+")
        moduli.append(mod)
        rems.append(dl)
        print(moduli)
        print(rems)
        print("_"*50)

n = 0
host, port =  "65.21.255.31", 10101
while True:
    r = remote(host, port)
    print(n)
    round(r)
    r.close()
    n += 1
    if prod(moduli) > 2**256:
        break
print(crt(rems, moduli))
