from sage.all import *
from output import n, enc_d, enc_phi, enc_flag
from Crypto.Util.number import long_to_bytes
e = 3

ed = enc_d
ep = enc_phi

print(n)
for k in range(1, 3):
    dphi = (pow(3 * e * k, -1, n) * (e **3 * ed - k**3 * ep -1)) % n
    
    A = (e * (e**3 * ed - 4 * k**3 * ep)) % n
    B = (k**4 * ep - k * 4 * ed * e**3) % n
    C = ((6 * k**2 * dphi**2 * e**2) - 1) % n

    m = Matrix(Zmod(n), [[A, B], [e, -k]])
    ans = m.solve_right(vector(Zmod(n), [-C, 1]))
    d = int(ans[0])
    phi = int(ans[1])

    a = randint(0, n)
    if (pow(a, phi, n) == 1):
        ans = pow(enc_flag, d, n)
        print(long_to_bytes(int(ans)))
