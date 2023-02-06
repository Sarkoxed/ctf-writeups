import re

from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import context, remote
from sage.all import PolynomialRing, Zmod, crt, product, randint, var

context.log_level = "error"


def lrs(p, a, b, x0, n):
    for i in range(n):
        x0 = (a * x0 + b) % p
    return x0


def get_ass(p):
    if (p - 1) % 5 != 0:
        return None

    ass = [1]
    while True:
        a = pow(randint(1, p - 1), (p - 1) // 5, p)
        if a != 1 and a not in ass:
            ass.append(a)
        if len(ass) == 5:
            break
    return ass[1:]


def get_a(ass, p, b, e):
    for k in range(4):
        tmp = []
        for i in range(5):
            tmp.append(int(lrs(p, ass[k], b, 11, i)) % 2)
        if not any(tmp[1:]):
            return ass[k]
    return None


host, port = "mc.ax", 31340
#host, port = "localhost", 17778
trie = 1

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

for i in range(5):
    print(f"seed {i}")
    r.sendline(str(lrs(p, a, b, 11, i)).encode())
    r.recvuntil(b"input seed:")

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

with open("final.py", "wt") as f:
    f.write(f"{ns, cs, rs, es =}")

g, gs = coppersmith(ns, cs, rs, e)
flag = g.small_roots(X=2 ** (54 * 8), beta=0.4)[0]
print(long_to_bytes(int(flag)))
