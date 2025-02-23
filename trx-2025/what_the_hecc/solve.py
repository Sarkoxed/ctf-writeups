from sage.all import HyperellipticCurve, GF, PolynomialRing
import itertools as it
from Crypto.Cipher import AES
import hashlib

p = 2**127 - 1
G = GF(p)
a, b = 57792482556163740063210341500068239889, 169237172037427005576500528337261655640
P = PolynomialRing(GF(p), "x")
x = P.gens()[0]
F = x**5 + a*x**3 + b*x
H = x**2 + x + 1

C = HyperellipticCurve(F, H)
J = C.jacobian()

P_Q_R = x**2 + 63302659844929880293283924307824630476*x + 147250528713145888320441019253715338546
alpha1, alpha2 = [z[0] for z in P_Q_R.roots()]
# A * alpha1 + B = y1 : y**2 + H(alpha1) * y - F(alpha1) = 0
# A * alpha2 + B = y2 : y**2 + H(alpha2) * y - F(alpha2) = 0
pos_ys = [z[0] for z in (x**2 + H(x=alpha1) * x - F(x=alpha1)).roots()]
pos_ys += [z[0] for z in (x**2 + H(x=alpha2) * x - F(x=alpha2)).roots()]

pos_PQRs = []
for y1, y2 in it.combinations(pos_ys, r=2):
    A = (y1 - y2) / (alpha1 - alpha2)
    B = y1 - alpha1 * A
    tmp = A * x + B
    if (tmp**2 + H * tmp - F) % P_Q_R == 0:
        pos_PQRs.append(J((P_Q_R, tmp)))

P_Q_S = x**2 + 149118285722446734984934788574031623199*x + 23310041014195484294124078181127671986
beta1, beta2 = [x[0] for x in P_Q_S.roots()]
pos_ys = [z[0] for z in (x**2 + H(x=beta1) * x - F(x=beta1)).roots()]
pos_ys += [z[0] for z in (x**2 + H(x=beta2) * x - F(x=beta2)).roots()]

pos_PQSs = []
for y1, y2 in it.combinations(pos_ys, r=2):
    A = (y1 - y2) / (beta1 - beta2)
    B = y1 - beta1 * A
    tmp = A * x + B
    if (tmp**2 + H * tmp - F) % P_Q_S == 0:
        pos_PQSs.append(J((P_Q_S, tmp)))


iv = bytes.fromhex('da122954201b841f01b85ab12da1ab3b')
ct = bytes.fromhex('b21a0a89502508119e2062a7145775418163d947b889b58e2ec88ad3907129fceff7c38b2721d6c89b16edf7a05153b6b54fa55c36f74d479f08a8afa2ca08c8')

for PQR, PQS in it.product(pos_PQRs, pos_PQSs):
    assert PQR[0] == P_Q_R
    assert PQS[0] == P_Q_S

    R_S = PQR - PQS
    rs = R_S[0].roots()
    if len(rs) == 0:
        continue
    
    def recover_one_root(alpha):
        gamma1, gamma2 = [z[0] for z in (x**2 + H(x=alpha) * x - F(x=alpha)).roots()]
        R1 = J((x - alpha, P(gamma1)))
        R2 = J((x - alpha, P(gamma2)))
        return R1, R2
    
    R1, R2 = recover_one_root(rs[0][0])
    Rs = [R1, R2]
    S1, S2 = recover_one_root(rs[1][0])
    Ss = [S1, S2]
    
    RS = []
    k1 = R1 - S1
    if (R1 - S1 == R_S):
        RS.append([R1, S1])
    if (R1 - S2 == R_S):
        RS.append([R1, S2])
    if (R2 - S1 == R_S):
        RS.append([R2, S1])
    if (R2 - S2 == R_S):
        RS.append([R2, S2])
    if (S1 - R1 == R_S):
        RS.append([S1, R1])
    if (S1 - R2 == R_S):
        RS.append([S1, R2])
    if (S2 - R1 == R_S):
        RS.append([S2, R1])
    if (S2 - R2 == R_S):
        RS.append([S2, R2])
    
    PQRS = []
    for R, S in RS:
        PQ1 = PQR - R
        rs = PQ1[0].roots()
        if len(rs) == 0:
            continue
        P1, P2 = recover_one_root(rs[0][0])
        Q1, Q2 = recover_one_root(rs[1][0])
        if P1 + Q1 + R == PQR and P1 + Q1 + S == PQS:
            PQRS.append([P1, Q1, R, S])
        if P1 + Q2 + R == PQR and P1 + Q2 + S == PQS:
            PQRS.append([P1, Q2, R, S])
        if P2 + Q1 + R == PQR and P2 + Q1 + S == PQS:
            PQRS.append([P2, Q1, R, S])
        if P2 + Q2 + R == PQR and P2 + Q2 + S == PQS:
            PQRS.append([P2, Q2, R, S])


        PQ2 = PQR - S
        rs = PQ2[0].roots()
        if len(rs) == 0:
            continue

        if P1 + Q1 + R == PQR and P1 + Q1 + S == PQS:
            PQRS.append([P1, Q1, R, S])
        if P1 + Q2 + R == PQR and P1 + Q2 + S == PQS:
            PQRS.append([P1, Q2, R, S])
        if P2 + Q1 + R == PQR and P2 + Q1 + S == PQS:
            PQRS.append([P2, Q1, R, S])
        if P2 + Q2 + R == PQR and P2 + Q2 + S == PQS:
            PQRS.append([P2, Q2, R, S])
        
    for P_, Q_, R_, S_ in PQRS:
        A = (P_[0], P_[1])
        B = (Q_[0], Q_[1])
        C = (R_[0], R_[1])
        D = (S_[0], S_[1])
        print(A, B, C, D)
        secret = hashlib.sha256(''.join(map(str, [A, B, C, D])).encode()).digest()
        cipher = AES.new(key=secret, mode=AES.MODE_CBC, iv=iv)
        m = cipher.decrypt(ct)
        print(m)
