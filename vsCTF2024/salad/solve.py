from pwn import remote
from hashlib import sha256
from sage.all import next_prime, GF, Ideal, ZZ
import time
import pickle
from find_solution import find_solution


host, port = "vsc.tf", 5003


def hash(msg):
    return sha256(msg).hexdigest()


def partial_hesh(msg):
    data = hash(msg)
    # split into blocks of len b bytes
    blocks = [data[i : i + (b // 4)] for i in range(0, len(data), (b // 4))]
    # convert to integers
    ints = [int(block, 16) for block in blocks]
    return ints  # return S.invert(ints)


o = 4
v = o**2
b = 256 // o
q = 2**b
q = next_prime(q)

F = GF(q)
R = F[",".join(f"v_{i}" for i in range(o + v))]
gs = R.gens()

solution = None
TARGET_MSG = b"can i maybe pls have a flag~ >w<"
hesh_input = partial_hesh(TARGET_MSG)
while solution is None:
    r = remote(host, port)
    r.recvline()

    polys = []
    for _ in range(4):
        polys.append(R(r.recvline().decode()))
    pickle.dump([o, v, b, q, polys, gs], open("polys.data", "wb"))


    cs = [poly - h for poly, h in zip(polys, hesh_input)]
    solution = find_solution(cs, R.gens(), o, R)
    if solution is None:
        r.close()
print(hesh_input)
print([poly.subs({z: x for z, x in zip(R.gens(), solution)}) for poly in polys])
r.sendline(TARGET_MSG)
r.sendline(str(list(solution)).encode())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
