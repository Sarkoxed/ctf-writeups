from sage.all import I, Matrix, e, pi, floor, identity_matrix, vector

ct = [
    (1614.41597751, 2440.04175266),
    (-239.31512831, 65.01569777),
    (-174.3244422, 623.0315122),
    (148.33319848, 107.54945904),
    (-80.39944861, -16.1430125),
    (106.05365816, 198.8020629),
    (252.91493127, 79.94326544),
    (-102.92505223, 220.19525344),
]
ct = [(round(x * 10**8), round(y * 10**8)) for x, y in ct]

zeta = e ** (2 * pi * I / 128)
zetas = [pow(zeta, 2 * i + 1) for i in range(8)]

scale = 100
M = Matrix(42 + 1, 42 + 2 * len(ct))
M.set_block(0, 0, identity_matrix(42) * scale)
M.set_block(42, 0, Matrix([-scale] * 42))

for i in range(len(ct)):
    c = zetas[i]
    zetai = [
        (floor((c**i).real() * 10**8), floor((c**i).imag() * 10**8)) for i in range(42)
    ]
    print(vector([x[0] for x in zetai]) * vector([ord("f")] * 42), ct[i][0])

    M.set_block(0, 42 + 2 * i, Matrix([x[0] for x in zetai]).T)
    M.set_block(0, 43 + 2 * i, Matrix([x[1] for x in zetai]).T)
    M[42, 42 + 2 * i] = -ct[i][0]
    M[42, 43 + 2 * i] = -ct[i][1]


print(vector([ord("f")] * 42 + [1]) * M)

for l in M.LLL():
    #    print(l)
    print(M.solve_left(l))

print(
    bytes(
        [
            76,
            49,
            108,
            95,
            49,
            53,
            95,
            52,
            108,
            108,
            95,
            121,
            48,
            117,
            95,
            110,
            51,
            51,
            100,
            95,
            116,
            48,
            95,
            98,
            114,
            51,
            52,
            107,
            95,
            116,
            104,
            51,
            95,
            51,
            110,
            99,
            48,
            100,
            51,
            114,
            33,
            33,
        ]
    )
)
