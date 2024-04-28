from sage.all import (
    Matrix,
    GF,
    GL,
    prod,
    var,
    PolynomialRing,
    discrete_log,
    gcd,
    randint,
    crt,
    lcm
)
from itertools import product


p = 14989068425250509519
pudge = 488021842552697485963550845809830956869265678611663884519824835144279897263760519070556811395650

# A = random_matrix(GF(p), 5,5)
A = Matrix(
    GF(p),
    [
        [
            2316580867395718488,
            48426743017495202,
            10035688260900924039,
            4231347989577694113,
            10589292030513420982,
        ],
        [
            13855044643446484404,
            5232761037656480890,
            8292975196384415335,
            6347855203040361884,
            1695816437660153737,
        ],
        [
            13046242976127835996,
            9475110516100642016,
            4727306285316450578,
            4641412090997841438,
            12402034468342504110,
        ],
        [
            2367861295557041099,
            7972370016088296064,
            2345756074442706631,
            5466959662134124819,
            7703316732710858490,
        ],
        [
            3154951152478314029,
            14631229995381692381,
            8791489668576804292,
            14058045966950055197,
            6886936172143671821,
        ],
    ],
)
# A_1 = PUDGE?
A_1 = Matrix(
    GF(p),
    [
        [
            10449681695550103501,
            1032827731769907364,
            8551846352768290089,
            2528206462071885652,
            4668517139358847432,
        ],
        [
            8129949521585158431,
            8663150094657298270,
            13611618663064384279,
            11990726265981907640,
            8736574751606166199,
        ],
        [
            13477489095760140976,
            4129645872383074495,
            802354481887101565,
            5918883130626557767,
            4293067273646165724,
        ],
        [
            3218110987866379647,
            13155490303126428937,
            10511509599742650284,
            10905345492015529131,
            8890727867148431908,
        ],
        [
            6267270344792504320,
            1272127850159541188,
            9155031196436204158,
            13829185043890037978,
            2887328975771996112,
        ],
    ],
)


def pUdge(s=1):
    a_1 = A
    if s == 1:
        return a_1
    a_2 = A_1
    if s == 2:
        return a_2
    s -= 2
    while True:
        a_n = a_2 * a_1
        a_1, a_2 = a_2, a_n
        if s == 1:
            return a_n
        s -= 1


# assert pUdge(2 ** 322 - 228) == A ** (flag + pudge)

# A_1 = A^3 (jordan based)
# pUdge(n) = A^(phi(n + 2) + 3 * phi(n + 3))
assert A_1 == A**3


# G1 = GL(5, GF(p))
# order = G1(A).order()
order = 756611975305664976948701508934220455553386636654110694421436693429248935533058528391714742723598
orders = [
    2,
    41,
    181,
    281,
    1021,
    252802471,
    7160174515257691,
    7340386104432179,
    2533264055405865190411771,
    5278912143021689094931,
]
orders = sorted(orders)
assert prod(orders) == order


def fib_real(n):
    a1, a2 = 0, 1
    for i in range(n - 1):
        a1, a2 = a2, a1 + a2
    return a2


# tmp = pUdge(20)
# assert tmp == A**(fib_real(20 - 2) + 3 * fib_real(20 -1))


def fib(n, p):
    G = GF(p)
    sq = G(5).sqrt()
    phi = (1 + sq) / 2
    psi = (1 - sq) / 2
    n %= p - 1
    return (pow(phi, n) - pow(psi, n)) / sq


def fib1(n, p):
    G = GF(p)
    sq = G(5).sqrt()
    phi = (1 + sq) / 2
    psi = (1 - sq) / 2
    n = (n - 2) % (p -1)
    res1 = (pow(phi, n) - pow(psi, n)) / sq
    n += 1
    res2 = (pow(phi, n) - pow(psi, n)) / sq

    alpha = res1 + 3 * res2

    n += 1
    assert (
        phi ** (2 * n) * (phi**-3 + 3 * phi**-2)
        + phi**n * (-alpha * sq * phi**-1)
        + (-1) ** n * (3 - phi)
        == 0
    )
    return alpha


m = 10_000
q = orders[-1]
assert pUdge(m) ** (order // q) == A ** (order // q * int(fib1(m, q)))


def pudge_extended(m, p):
    return A ** int(fib(m - 2, p) + 3 * fib(m - 1, p))


for i in range(5, 100):
    assert pUdge(i) == pudge_extended(i, orders[-1])


def dlp(alpha, p):
    G = GF(p)
    sq = G(5).sqrt()
    phi = (1 + sq) / 2

    # alpha = fib(n - 2, p) + 3 * fib(n  - 1, p)
    # assert phi**(2* n) * (phi**-3 + 3 * phi**-2) + phi**n * (-alpha * sq * phi**-1) + (-1)**n *(3 - phi) == 0
    # return

    A = phi**-3 + 3 * phi**-2
    B = -alpha * sq * phi**-1
    C = 3 - phi

    x = var("x")
    P = PolynomialRing(GF(p), x)

    solutions = []
    for i in range(2):
        poly = A * P(x**2) + B * P(x) + C * (-1) ** i
        a = poly.roots()
        if len(a) == 0:
            continue
        a1, a2 = a
        a1 = a1[0]
        a2 = a2[0]

        try:
            d1 = discrete_log(a1, phi)
            if fib1(int(d1), p) == alpha:
                solutions.append(d1)
                print(d1)
        except Exception as e:
            print(e)
        try:
            d2 = discrete_log(a2, phi)
            if fib1(int(d2), p) == alpha:
                solutions.append(d2)
                print(d2)
        except Exception as e:
            print(e)
    return solutions, phi.multiplicative_order()


# p = orders[-3]
# t1 = randint(1, p - 1)
# alpha = fib1(t1, p)
# solutions, o1 = dlp(alpha, p)
# print(solutions)
# print(t1 % o1)

#m = randint(0, 10000)  # 2**322 - 228
#print(m)
#
#ords, sols = [], []
#for p in orders[2:-2]:
#    print(f"{p = }")
#    alpha = fib1(m, p)
#    cursolv, o = dlp(alpha, p)
#    print(cursolv)
#    ords.append(o)
#    sols.append(cursolv)
#    print("_" * 20)
#
#print(sols)
#for i in range(2):
#    print(i)
#    print()
#    for s in product(*sols):
#        try:
#            f = [i] + list(s)
#            print(f)
#            print(ords)
#            K = crt(f, ords)
#            print(K)
#        except Exception as e:
#            print(e)
#        print()

m = 2**322 - 228

fibs = [1] + [int(fib1(m, p)) for p in orders[1:]]
res = crt(fibs, orders) - pudge
print(int(res).to_bytes(50, 'big'))

print()

#m = 1500
#
#assert pUdge(m) == A**(fib_real(m - 2) + 3 * fib_real(m - 1))
#print(A**order)
#print()
#print((fib_real(m - 2) + 3 * fib_real(m - 1)) % order)
#assert prod(orders) == order
#
#print((fib_real(m - 2) + 3 * fib_real(m - 1)) % 2)
#fibs = [0] + [int(fib1(m, p)) for p in orders[1:]]
#res = crt(fibs, orders)
#print(res)
