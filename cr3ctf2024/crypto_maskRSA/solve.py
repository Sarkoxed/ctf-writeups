from sage.all import Zmod, Matrix, PolynomialRing, var
from gmpy2 import iroot
#from data import masks, enc, n
from data import masks, enc, n
from time import time

x, y = var("x y")

def find_particular_solution(z, w):
    P = PolynomialRing(Zmod(n), [x, y])
    M = Matrix(P, 20, 18)
    for i, (mask, c) in enumerate(zip(masks, enc)):
        poly = P(((x + y) * mask + y)**17 - c)
        y_powers = [poly.coefficient({P(z): i}) for i in range(18)]
        M.set_block(i, 0, Matrix(y_powers))

    P2 = PolynomialRing(Zmod(n), w)
    aaa = P2(M[:-2].det())
    print(aaa)
    s0, s1 = aaa.coefficients()
    respoly = s0 + s1 * P2(w**17)
    respoly = respoly.monic()
    print(respoly)
    a, b = respoly.coefficients()
    print(a, b)

    tmp = iroot(int(-a), 17)
    print(tmp)
    return int(tmp[0])


start = time()
x1 = find_particular_solution(y, x)
end = time()
print("Passed: ", end - start)
start = time()
y1 = find_particular_solution(x, y)
end = time()
print("Passed: ", end - start)

print(x1.to_bytes(14, 'big'))
print(y1.to_bytes(14, 'big'))
