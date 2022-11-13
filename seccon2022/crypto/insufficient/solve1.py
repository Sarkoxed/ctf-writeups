from Crypto.Util.number import long_to_bytes
from sage.all import (
    QQ,
    ZZ,
    Matrix,
    ceil,
    floor,
    gcd,
    identity_matrix,
    matrix,
    vector,
    zero_vector,
)

from output import p, params, ct


def hadamardratio(v):
    m = matrix(v)
    prod = 1
    for i in range(len(v)):
        prod *= v[i].norm()
    return pow((abs(m.det()) / prod).n(), 1 / len(v))


def nearest(x):
    if abs(floor(x) - x) < 0.5:
        return floor(x)
    return ceil(x)


def gen_matr(p, params, t=1):
    m = len(params)
    d = 6
    M = Matrix(QQ, m + d, m + d)
    M.set_block(0, 0, identity_matrix(m) * p)
    M.set_block(m, m, identity_matrix(d) * t)
    h = []
    for i in range(m):
        x, y = params[i][0]
        h.append(params[i][1])
        inte = matrix([x, x**2, x**3, y, y**2, y**3]).T
        M.set_block(m, i, inte)
    h = h + [0] * d
    return M, vector(h)


def Babai_algorithm(base, vec):
    m = Matrix(base)
    sol = m.solve_left(vec)
    sol = vector([nearest(x) for x in sol])
    ans = zero_vector(len(base))
    for i in range(len(base)):
        ans += vector(base[i]) * sol[i]
    return ans


a, b = 0, p
while True:
    t = (a + b) // 2
    M, h = gen_matr(p, params, t)
#    print(hadamardratio(list(M)).n())

    m = M.LLL()
    m = [x for x in m]
#    print(hadamardratio(m).n())

    r = Babai_algorithm(m, h)
#    print(r, h, r - h)
    r = Matrix(M).solve_left(r)
    z = int(abs(r[-2])).bit_length()
    if (
        z >= 127
        and z <= 128
        and all(x > 0 and int(x).bit_length() <= 128 for x in r[-6:])
    ):
        print(t)
        break
    elif z > 128:
        print("bigger", z.bit_length())
        a = t + 1
    else:
        print("less")
        b = t - 1
    if b <= a + 1:
        break
    print(a, b)


a1, a2, a3, b1, b2, b3 = r[-6:]
rs = []
for _ in range(4):
    x, y = params[_][0]
    w = params[_][1]
    r0 = (
        w - (a1 * x + a2 * x**2 + a3 * x**3 + b1 * y + b2 * y**2 + b3 * y**3)
    ) % p
    rs.append(r0)
r1, r2, r3, r4 = rs
c = gcd([r2 - r1, r3 - r2, r4 - r3])
z1 = floor((r1 - 2**128) / c)  # using boundaries for s
z2 = ceil((r1 - 2**127) / c)

for z in range(z1, z2 + 1):
    s = r1 - c * z
    if s > 0 and int(s).bit_length() == 128:
        break

coeffs = [a1, a2, a3, b1, b2, b3, c, s]
coeffs = [int(x) for x in coeffs]

key = int(0)
for coeff in coeffs:
    key <<= 128
    key ^= coeff


flag = ct ^ key
print(long_to_bytes(flag))
