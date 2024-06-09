from parse import C, pkey
from sage.all import Matrix, prod, gcd, GF, QQ
import itertools

hz = [Matrix(x) for x in pkey[:19]]
ms = [Matrix(x) for x in pkey[19:19 + 19]]
M = Matrix(pkey[38:][0])
C = Matrix(C)

def get_permutation(ms, tmpm, perm):
    print(perm)
    if len(perm) == len(ms):
        if tmpm.is_one():
            return perm
        return None

    for i in range(len(ms)):
        if i not in perm:
            t1 = ms[i]**-1
            m1 = tmpm * t1
            if (all(x.is_integer() for y in m1 for x in y)):
                res = get_permutation(ms, m1, [i] + perm)
                if res is not None:
                    return res
    return None

#print(get_permutation(ms, M, []))
#perm = [0, 6, 8, 3, 18, 9, 4, 12, 11, 7, 2, 1, 16, 14, 17, 5, 13, 10, 15]

#print(ms[0] * M**-1 * hz[0] * M)

f00 = []
for A, R in zip(ms, hz):
    f00.append(((M * A)**(-1) * R * M)[0][0])
a0, b0 = f00[0].numerator(), f00[0].denominator()
asbs = []
for i in range(1, len(f00)):
    ai, bi = f00[i].numerator(), f00[i].denominator()
    asbs.append(a0 * bi - b0 * ai)

#p = 68072599015191957577350893302343041540755881407848594728366324833646985020777
p = 95132089008518064204719248223853908833679528919258368021624722196200223276261

re_sperm = Matrix(QQ, Matrix(GF(p), M)**-1 * Matrix(GF(p), C) * Matrix(GF(p), M))

A20 = ((M * A)**(-1) * R * M) % p
re_ms = [A * Matrix(QQ, A20) for A in ms]

re_tries = [M * X * M**-1 % p for X in re_ms]
print(re_tries == hz)
exit()
p1 = [11, 13, 17, 9, 18, 8, 6, 15, 10, 0, 3, 14, 5, 4, 2, 16, 1, 7, 12]

#print(prod(re_ms[i] for i in p1).change_ring(GF(p)) == re_sperm.change_ring(GF(p)))
print(prod(hz[i] for i in p1).change_ring(GF(p)) == C.change_ring(GF(p)))

#for i in range(len(re_ms)-1):
#    for j in range(i + 1, len(re_ms)):
#        tmpA = Matrix(QQ, re_sperm * re_ms[i]**-1 * re_ms[j]**-1 % p)
#        c1 = sum(int(x).bit_length() for y in tmpA for x in y) / 25
#        print(i, c1)
#        print()

#tmpA = Matrix(QQ, re_sperm.change_ring(GF(p)) * Matrix(GF(p), A))
#
#for y in tmpA:
#    for x in y:
#        print(int(x).bit_length())
#get_permutation(re_ms, re_sperm, [])
