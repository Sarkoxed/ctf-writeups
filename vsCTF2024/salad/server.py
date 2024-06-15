from ov import *
from sage.all import next_prime, PolynomialRing, GF
from hashlib import sha256
from ast import literal_eval

o = 4
v = o**2
b = 256 // o
q = 2**b
q = next_prime(q)

S = Salad(o, v, q)

def hash(msg):
    return sha256(msg).hexdigest()


def hesh(msg):
    data = hash(msg)
    # split into blocks of len b bytes
    blocks = [data[i : i + (b // 4)] for i in range(0, len(data), (b // 4))]
    # convert to integers
    ints = [int(block, 16) for block in blocks]
    print(f"{ints=}")
    return S.invert(ints)


F = GF(q)
R = F[",".join([f"v_{i}" for i in range(o + v)])]
x = R.gens()
pk = S.raw_eval(x)

for eq in pk:
    print(eq % q)

TARGET_MSG = b"can i maybe pls have a flag~ >w<"
FLAG_SIG = S.eval(hesh(TARGET_MSG))
while True:
    msg = input("Enter message: ").encode()
    if msg == TARGET_MSG:
        sig = literal_eval(input("Enter signature: "))
        if S.eval(sig) == FLAG_SIG:
            print(open("flag.txt").read().strip())
            exit(1)
        else:
            print("NO")
            exit(1)
    h = hesh(msg)
    c = S.eval(h)
    print(c)
