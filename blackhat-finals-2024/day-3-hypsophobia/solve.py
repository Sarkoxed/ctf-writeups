from pwn import remote
import re
from base64 import urlsafe_b64decode
import itertools
from sage.all import EllipticCurve, GF, factor, gcd, prod, crt, Zmod

def parse_header(r):
    for _ in range(13):
        (r.recvline())

def go(r):
    r.sendline(b'g')
    r.recvuntil(b'goooo ~ !!!')
    response = r.recvline().decode()
    response += r.recvline().decode()
    response += r.recvline().decode()
    response += r.recvline().decode()
    response += r.recvline().decode()
    response += r.recvline().decode()
    response += r.recvline().decode()
    response += r.recvline().decode()
    #print(response)

    floor = int(re.findall(r'got to floor (.*) but', response)[0])
    x = int.from_bytes(urlsafe_b64decode(re.findall(r'BLEUUUURGHHH(.*)\n', response)[0] + "====="), 'big')
    return floor, x

def get_double(r, scalars, xs):
    c = 0
    while True:
        c += 1
        sc, x = go(r)
        scalars.append(sc)
        xs.append(x)
        
        if sc * 2 in scalars:
            a = scalars.index(sc)
            b = scalars.index(sc * 2)
            break
        elif sc & 1 == 0 and sc // 2 in scalars:
            a = scalars.index(sc // 2)
            b = scalars.index(sc)
            break
    print(f"Queries per double: {c}")
    return xs[a], xs[b], scalars, xs

def recover_mod(r, n=3):
    doubles = []
    scalars, xs = [], []
    for _ in range(n):
        xa, xb, scalars, xs = get_double(r, scalars, xs)
        doubles.append((xa, xb))

    a, b = 0, 0
    for A, B in itertools.product(range(256), repeat=2):
        relations = []
        for xa, xb in doubles:
            relation = (xa**2 - A)**2 - 8 * B * xa - xb * 4 * (xa**3 + A * xa + B)
            relations.append(relation)
        Ps = [p for p, e in factor(gcd(relations)) if p.bit_length() == 32]
        if len(Ps) == 64:
            a, b = A, B
            return Ps, A, B, scalars, xs

def recover_flag(scalars, xs, Ps, A, B):
    goodies = []
    for p in Ps:
        e = EllipticCurve(GF(p), [A, B])
        for s, x in zip(scalars, xs):
            if gcd(s, e.order()) == 1 and GF(p)(x**3 + A*x + B).is_square():
                goodies.append((p, s, x))
                break
    
    rems, mods = [], []
    for p, s, x in goodies:
        e = EllipticCurve(GF(p), [A, B])
        T = pow(s, -1, e.order()) * e.lift_x(GF(p)(x))
        rems.append(int(T[0]))
        mods.append(p)
    return rems, mods

host, port = "localhost", 1337
rems, mods = [], []
while True:
    r = remote(host, port)
    parse_header(r)
    Ps, A, B, scalars, xs = recover_mod(r, n=3)
    r.close()
    nrems, nmods = recover_flag(scalars, xs, Ps, A, B)

    rems += nrems
    mods += nmods

    f = crt(rems, mods).to_bytes(256, 'big')
    if b'BHFlag' in f:
        print(f)
        break
