import sys
from sage.all import factor

def find_size():
    x = 100691360
    for i in range(1, 17):
        c = factor(x - i)
        if (x - i) % 6 == 0 and sum(x[1] for x in c) > 4:
            print(c, i)

if len(sys.argv) == 3:
    find_size()

f = open(sys.argv[1], 'rb').read()
w, h = 2671, 103

t1 = b"P6\n" + f"{w} {h}".encode() + b'\n65535\n' + f[:w * h * 6]
with open("govno.ppm", 'wb') as f:
    f.write(t1)

#pixels = []
#for i in range(h):
#    cur_row = f[i * w * 6: (i + 1) * w * 6]
##    print(len(cur_row) // 6)
##    print(cur_row)
#
#    for i in range(0, w * 6, 6):
#        cur_triplet = cur_row[i:i+6]
#        pixels.append(cur_triplet)
#        r = cur_triplet[:2]
#        g = cur_triplet[2:4]
#        b = cur_triplet[4:]
#        if cur_triplet != b'\xff' * 6:
#            print(r.hex(), g.hex(), b.hex())
#
#print(len(pixels))
#print(len(set(pixels)))
#print(set(pixels))
