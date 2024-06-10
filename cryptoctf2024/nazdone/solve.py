import tqdm
from output import n, c
from sage.all import PolynomialRing, ZZ, factor, var, crt

def rebase(n, b):
    if n < b:
        return [n]
    else:
        return [n % b] + rebase(n//b, b)

x = var('x')
P = PolynomialRing(ZZ, x)
#for m in range(3, 10000):
#     tmp = rebase(n, m)
#     k1 = factor(P(tmp))
#     if len(k1) >= 3:
#         print(m, k1)

tmp = rebase(n, 19)
t1, t2, t3 = [x[0] for x in factor(P(tmp))]
print(t1)
print(t2)
print(t3)
p = t1(x=19)
q = t2(x=19)
r = t3(x=19)

assert p * q * r == n

for z in range(10, 20):
    tmp_pow = 19**3 + z - 2
    try:
        p1 = pow(tmp_pow, -1, p - 1)
        p2 = pow(tmp_pow, -1, q - 1)
        p3 = pow(tmp_pow, -1, r - 1)

        m1 = pow(c, p1, p)
        m2 = pow(c, p2, q)
        m3 = pow(c, p3, r)
        res = crt([m1, m2, m3], [p, q, r])
        print(int(res).to_bytes(100, 'big'))
    except Exception as e:
        print(e)
        continue
