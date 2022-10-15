from output_updated import PUBKEYS as pks
from output_updated import ENCS as es
from Crypto.Util.number import long_to_bytes
from sage.all import *
ans1 = b''

for p, c in zip(pks, es):
    n, s = p
    su = ((n - 1) // 2**134) % 2**134
    pro = (n - 1 - 2**134 * su ) // 2**(134 * 2)
    var('x')
    t = x**2 - su * x + pro
    r1, r2 = t.roots()
    r1 = r1[0]
    r2 = r2[0]
    print(int(r1).bit_length())
    p = 1 + 2**134 * int(r1)
    q = 1 + 2**134 * int(r2)
    g = GF(p)

    ss = g(c)**r1
    t1 = discrete_log(g(ss), g(s))
    rr = pow(int(r1), -1, p)
    tt = g(t1) * g(rr)
    tt = int(tt)
    ans = int(tt)
    ans1 += long_to_bytes(ans)
print(ans1)
