from factordb.factordb import FactorDB
from sage.all import *
from kek import db
from itertools import combinations
from params import g, G, n, x, y, c, e
from Crypto.Util.number import long_to_bytes

db.append((x, y, n, g, G, c, e))

d = abs(x - y)
#assert d % G == 0

q = FactorDB(d)
q.connect()
l = q.get_factor_list()

prob_phiphis = []
for num in range(1, len(l)+1):
    for comb in combinations(l, num):
        d1 = d // product(comb)
        tmp = int(n).bit_length() - int(d1).bit_length()
        if tmp >= 0 and tmp <= 4:
            prob_phiphis.append(d1)
prob_phiphis = list(set(prob_phiphis))
prob_phiphis.append(d)

for ph in prob_phiphis:
    t = n - 2 * ph + 9
    if t % 3 != 0 or t < 0:
        continue
    su = t // 3
    var('x')
    s = x**2 - su * x + n
    print(s)
    k = s.roots()
    if k[0][0].is_integer():
        print(k)


with open("kek.py", "wt") as f:
    f.write(f"db = {db}")
