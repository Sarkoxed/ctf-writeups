from sage.all import PolynomialRing, ZZ, var, log


x = var("x")
R = PolynomialRing(ZZ, x)
g = R(x**2 + x + 2)

def multiply_by(po):
    res = [2 * i for i in po]
    res = [a + b for a, b in zip(po, [0] + [po])] + [po[-1]]
    res = [a + b for a, b in zip(po, [0, 0] + [po])] + [po[-1]]
    return res


def find_poly(beta, cursor, n, d):
    if cursor == d - 1:
        assert len(beta) == d - 1

        if (beta[-1] + beta[-2] not in [-1, 0, 1] or beta[-1] not in [-1, 0, 1]):
            return None

        f1 = R(beta)
        f2 = f1 * g + n
       
        d1 = f2.degree()
        if f2.list().count(0) < 2 * d1 // 3 - 3:
            return None
        
        print("Pobeda")
        return f2

    if cursor == 0:
        if n & 1 == 0:
            beta0 = - n // 2
            res = find_poly([beta0], 1, n, d)
            if res is not None:
                return res
        else:
            for beta0 in [(-1 - n)//2, (1 - n) // 2]:
                res = find_poly([beta0], 1, n, d)
                if res is not None:
                    return res
        return None

    if cursor == 1:
        beta0 = beta[-1]
        if beta0 & 1 == 0:
            beta1 = - beta0 // 2
            res = find_poly(beta + [beta1], 2, n, d)
            if res is not None:
                return res
        else:
            for beta1 in [(-1 - beta0)//2, (1-beta0)//2]:
                res = find_poly(beta + [beta1], 2, n, d)
                if res is not None:
                    return res
        return None

    beta_t = beta[-2] + beta[-1]
    if beta_t & 1 == 0:
        beta1 = -beta_t // 2
        res = find_poly(beta + [beta1], cursor + 1, n, d)
        if res is not None:
            return res
    else:
        for beta1 in [(-1 - beta_t)//2,  (1 - beta_t)//2]:
            res = find_poly(beta + [beta1], cursor + 1, n, d)
            if res is not None:
                return res
    return None

from pwn import remote
import re
host, port = "02.cr.yp.toc.tf", 37771
r = remote(host, port)
r.recvline()
r.recvline()
r.recvline()
r.recvline()

for _ in range(1, 12):
    print(r.recvline())
    n = int(re.findall(r'n = (.*),', r.recvline().decode())[0])
    print(f"{n = }")
    v = int(2 * log(n) - 1)
    for d in range(max(v, 3), 100):
        print(d)
        #print(f"{d=}")
        res = find_poly([], 0, n, d)
        if res is not None:
            break
    print(res)
    r.sendline(str(res).encode())
r.interactive()
from random import randint
#for i in range(1, 40):
#    print(i)
#    n = randint(2**i, 2**(i + 1))
#    v = int(2 * log(n) - 1)
#    for d in range(max(v, 4), v + 40):
#        res = find_poly([], 0, n, d)
#        if res is not None:
#            break
#    if not res:
#        print(f"{n  = }")
