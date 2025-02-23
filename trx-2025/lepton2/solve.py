from pwn import remote
import re
from sage.all import prod, EllipticCurve, GF
from tqdm import tqdm
from hashlib import sha256
from Crypto.Cipher import AES

ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)


host, port = "lepton2.ctf.theromanxpl0.it", 7012
r = remote(host, port)

secret_vector = [0 for _ in range(len(ells))]
is_set = False

for i, e in tqdm(enumerate(ells), total=len(ells)):
    a2 = re.findall(r'montgomery curve: (.*)\n', r.recvline().decode())[0]
    r.recvline()
    E = EllipticCurve(F, [0, a2, 0, 1, 0])
    P = E.gens()[0]
    P *= P.order() // e # checking wheter the kernel of an isogeny contains this factor
    r.sendline(f"{P[0]}, {P[1]}".encode())
    res = r.recvline()
    if b"Invalid input" in res:
        secret_vector[i] = 1
    elif not is_set:
        E_ct = E
        P_ct = P
        ct = bytes.fromhex(res.strip().decode())
        is_set = True

def walk_isogeny(E, exponent_vector):
    P = E.random_point()
    o = P.order()
    order = prod(ells[i] for i in range(len(ells)) if exponent_vector[i] == 1)
    while o % order:
        P = E.random_point()
        o = P.order()
    P = o // order * P
    phi = E.isogeny(P, algorithm='factored')
    E = phi.codomain()
    return E, phi

M, phi = walk_isogeny(E_ct, secret_vector)
M_final = M.montgomery_model()
phi = M.isomorphism_to(M_final) * phi

Q = phi(P_ct)
secret_key = sha256(str(Q.xy()[0]).encode()).digest()
cipher = AES.new(secret_key, AES.MODE_ECB)
print(cipher.decrypt(ct))
