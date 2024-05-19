from pwn import remote
from sage.all import Matrix, GF, identity_matrix

p = (2 ** 31) - 1
F = GF(p)
FLAG_N = 55

def serialize_mtx(mtx):
    rows = []
    for row in mtx.rows():
        rows.append(','.join(str(elem) for elem in row))
    return '[' + ';'.join(rows) + ']'


def deserialize_mtx(mtx):
    print(mtx)
    rows = mtx.strip('[]\n').split(';')
    rows = [[int(num) for num in row.split(',')] for row in rows]
    return Matrix(F, rows)

host, port = "1337.sb",  20000
r = remote(host,port)
r.recvline()
print(r.recvline())
r.sendline(input().encode())

mtx = identity_matrix(FLAG_N)
deser = serialize_mtx(mtx)

r.recvline()
r.sendline(deser.encode())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())

res = "[99;114;51;123;49;95;104;48;112;51;95;121;48;117;95;119;51;114;101;110;116;95;116;82;121;49;110;71;95;116;48;95;102;49;78;68;95;99;48;77;109;85;116;49;110;103;95;109;52;116;114;49;120;33;125]"
print(bytes(list(deserialize_mtx(res).T[0])))
