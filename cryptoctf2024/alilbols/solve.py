from output import h, c
from sage.all import gcd, Matrix, sqrt
from tqdm import tqdm


def find():
    t1 = max(h, c)
    d = 1
    while 4 * 10 ** (2 * d) < t1 or gcd(h, 10 * d) != 1:
        d += 1
    return d


# print(find())
d = 563

for d in tqdm(range(d, d + 500)):
    try:
        assert gcd(h, 10 * d) == 1

        q = 4 * 10 ** (2 * d)
        M = Matrix([[1, 0], [h, -q]]).T
        T = M.LLL()

        f1, g1 = T[0]
        assert f1 * g1 > 0
        # f1, g1 = T[1] % q
        f1 = abs(f1)
        g1 = abs(g1)

        assert gcd(f1, 10 * g1) == 1

        assert g1 < int(sqrt(2) * 10**d)
        assert g1 > 10**d

        assert f1 < int(sqrt(2) * 10**d)

        assert (g1 * pow(f1, -1, q) % q) == h

        # print(d, "here")
        # print(f1, g1)

        a = ((c * f1) % q) * pow(f1, -1, g1) % g1
        r1 = ((c * f1) % q) * pow(g1, -1, f1) % f1  # r mod (f1)

        # print(r1)
        # print(a)

        tmp = (10**d // 2 - r1) // f1
        assert tmp >= 0

        while r1 < 10**d // 2 and a - r1 > 0:
            print((a - r1).to_bytes(256, "big"))
            r1 += f1
    except:
        continue
