from sage.all import next_prime, Matrix, GF, identity_matrix
from random import randint
from out import s
n = 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859

a = randint(1, n)
seed0 = randint(1, n)
seed = seed0
maxx = 2**768

s = [0] + s
#rds = []
#for i in range(20):
#    rd = randint(-maxx, maxx)
#    rds.append(rd)
#    seed = (a * seed + rd) % n
#    s.append(seed)
#
##s = [seed0] + [(seed + maxx) % n for seed in s[1:]]
#
#for i in range(1, len(s)):
#    assert s[i] == (a * s[i-1] + rds[i-1])%n

us = [(-s[i] * pow(s[1], -1, n)) % n for i in range(2, len(s) - 1)]
vs = [(-(s[i + 1] - s[2] * pow(s[1], -1, n) * s[i])) % n for i in range(2, len(s) - 1)]

#for i in range(len(us)):
#    tmp = rds[i + 2] + us[i] * rds[1] + vs[i]
#    assert (tmp % n) == 0

MMM = len(us)
M = Matrix(MMM + 2)
M.set_block(0, 0, identity_matrix(MMM) * n)
M.set_block(MMM, 0, Matrix(us))
M.set_block(MMM + 1, 0, Matrix(vs))
M[MMM, MMM] = 1
M[MMM + 1, MMM + 1] = maxx

for l in M.LLL():
    if all(abs(x) <= maxx for x in l):
        rds1 = l[:-1]
        break

a1 = (s[2] - rds1[-1]) * pow(s[1], -1, n) % n
print(a1.to_bytes(40, 'big'))
