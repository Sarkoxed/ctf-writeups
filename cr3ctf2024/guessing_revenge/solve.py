from pwn import remote
from sage.all import Matrix, GF, identity_matrix

p = (2**31) - 1
F = GF(p)
FLAG_N = 55


def serialize_mtx(mtx):
    rows = []
    for row in mtx.rows():
        rows.append(",".join(str(elem) for elem in row))
    return "[" + ";".join(rows) + "]"


def deserialize_mtx(mtx):
    rows = mtx.strip("[]\n").split(";")
    rows = [[int(num) for num in row.split(",")] for row in rows]
    return Matrix(F, rows)


from itertools import permutations


def get_permutations():
    perms = []
    for x in permutations([[1, 0, 0], [0, 1, 0], [0, 0, 1]]):
        perms.append(Matrix(F, x))
    return perms[1:]


#host, port = "localhost", 3000
host, port = "1337.sb",  20004
r = remote(host, port)
r.recvline()
print(r.recvline())
r.sendline(input().encode())

r.recvline()

mtx = identity_matrix(F, FLAG_N)

perms = get_permutations()
print(perms)
rets = []
for perm in perms:
    mtx.set_block(0, 0, perm)
    assert mtx.det() != 0
    ser = serialize_mtx(mtx)
    r.sendline(ser.encode())
    ret_ = r.recvline()
    ret = deserialize_mtx(ret_.decode())
    rets.append(mtx.inverse() * ret)

print(bytes(list((rets[0] + rets[1] + rets[4] - rets[2] - rets[3]).T)[0]))
