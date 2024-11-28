from challenge import Random
from random import randint
from tqdm import tqdm
import multiprocessing as mp
from termcolor import colored
from queue import Queue
from litecache import Cache
from datetime import datetime

bitstream = '10010111100001011011001010111001011011010101010011010111010011010111010101011000011010010111000001011000000100100110111111010101010101100011110101010100010100110111100010011000000000011111001101000010101110110001101001011010010101101100010111000110001101100001011111111101001101110101010111000010011010000100011110000001010100100001100110101000100111010100001110001010100110011100100110111011001010011010010110001000001000111010011100001011110000000001101111001101011110100010111101111101100101010101110100010000111111100001110001101111010110011001010100011010110000110011011111111001011111000001010011100101010100001101010110100100101100000111001001101110000000000110010111100010011000010010010000011110011010101111011110111000001001011000110000101001001001110000100111001001101000011110011011101100'

class ServerBitstream:
    def __init__(self):
        self.bitstream = bitstream
        self.state = 0
        self.bitcounts = [4, 7, 9, 32]
        self.counts = [0, 0, 0, 0]
        self.target_counts = [100, 13, 4, 1]
        self.bounds = [10, 80, 320, 1000]

    def next(self):
        tar = self.bitcounts[self.state]
        ret, self.bitstream = self.bitstream[:tar], self.bitstream[tar:]
        if len(ret) != tar:
            return None, None, None
        return int(ret, 2), 2**tar, self.bounds[self.state]

    def passed(self):
        self.counts[self.state] += 1
        if self.counts[self.state] == self.target_counts[self.state]:
            self.state += 1

class UserBitstream:
    def __init__(self, seed):
        self.rand = Random(seed)
        self.state = 0
        self.bitcounts = [4, 7, 9, 32]
        self.counts = [0, 0, 0, 0]
        self.target_counts = [100, 13, 4, 1]
        self.bounds = [10, 80, 320, 1000]

    def next(self):
        tar = self.bitcounts[self.state]
        return self.rand.GetRandBits(tar), 2**tar, self.bounds[self.state]

    def passed(self):
        self.counts[self.state] += 1
        if self.counts[self.state] == self.target_counts[self.state]:
            self.state += 1


def brute_seed(range_):
    passed = 0
    c = Cache("blackhat", "gatcha")
    if "minw" not in c:
        c["minw"] = 2**32
        c["ts"] = datetime.now()

    for i in range_:
        seed = randint(0, 2**61)
        R = UserBitstream(seed)
        SR = ServerBitstream()
    
        found = True
        tmpassed = 0
        while SR.state < 4:
            v, bs2, bo2 = SR.next()
            if v is None:
                found = False
    #            print(f"overflow over {len(bitstream)} bits on server...")
                break
    
            u, bs1, bo1 = R.next()
            assert bs1 == bs2
            assert bo1 == bo2
            w = (u + v) % bs1
            if w < bo1:
                tmpassed += 1
                R.passed()
                SR.passed()
            elif bo1 == 1000:
                if c["minw"] > w:
                    t = datetime.now()
                    print(colored(f"New goal reached: {w=} which is {w.bit_length()}.bits. T: {t}", 'green'))
                    delta = t - c["ts"]

                    c["minw"] = w
                    c["ts"] = t
                    print(f"Delta: {delta.total_seconds()}")

        if found:
            print(seed)
            exit(0)

#np = 10
#ranges = [range(2**32 // np) for _ in range(np)]
#
#with mp.Pool(np) as p:
#    p.map(brute_seed, ranges)

# final checks
seed = 921205744651925343

from challenge import HASH, FLAG
R_ = Random(int(HASH(FLAG).digest().hex(), 16))
assert R_.GetRandBits(len(bitstream)) == int(bitstream, 2)


R_ = Random(int(HASH(FLAG).digest().hex(), 16))
SR = ServerBitstream()
R = UserBitstream(seed)

while SR.state < 4:
    v, bs2, bo2 = SR.next()
    v1 = R_.GetRandBits(bs2.bit_length() - 1)
    #print(v, v1, w, SR.bounds[SR.state])
    if v is None:
        found = False
        #print(f"overflow over {len(bitstream)} bits on server...")
        break
    
    u, bs1, bo1 = R.next()
    assert bs1 == bs2
    assert bo1 == bo2
    w = (u + v) % bs1
    print(v, v1, w, SR.bounds[SR.state], bs2, bo2, u)
    assert v == v1
    if w < bo1:
        R.passed()
        SR.passed()
