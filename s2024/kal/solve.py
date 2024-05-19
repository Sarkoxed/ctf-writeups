from z3 import *
import struct
sol1 = "b724600535316972"

def get_sol2():
    local_10 = [0]*8
    local_18 = [0]*8
    local_10[0] = 5;
    local_10[1] = 0xaa;
    local_10[2] = 0x32;
    local_10[3] = 0xad;
    local_10[4] = 0xb4;
    local_10[5] = 0x15;
    local_10[6] = 0x20;
    local_10[7] = 0x8f;
    local_18[0] = 0x28;
    local_18[1] = 0x19;
    local_18[2] = 0xf3;
    local_18[3] = 0x59;
    local_18[4] = 0x7d;
    local_18[5] = 0x42;
    local_18[6] = 0x16;
    local_18[7] = 0xcb;
    return bytes([k^v for k, v in zip(local_10, local_18)]).hex()

sol2 = get_sol2()

def get_sol3():
    def fib(n):
        a, b = 0, 1
        for _ in range(n):
            a, b = b, a + b
        return a
    return struct.pack("I", fib(0x2e)).hex()

sol3 = get_sol3()

def get_sol4():
    return struct.pack("I", (0xc945c42+0x69b43d76)//0xb).hex()

sol4 = get_sol4()

def get_sol5():
    a = [0]*4
    b = [0]*4
    c = [0]*4
    d = [0]*4
    e = [0]*4
    a[0] = 0x11;
    a[1] = 0x12;
    a[2] = 0x1a;
    a[3] = 2;
    b[0] = 0x10cd6;
    b[1] = 0xd360;
    b[2] = 0x17c87;
    b[3] = 0x3b9e;
    c[0] = 9;
    c[1] = 0x20;
    c[2] = 0x1d;
    c[3] = 8;
    d[0] = 0x4f0a;
    d[1] = 0xcff8;
    d[2] = 0x151a7;
    d[3] = 0x1676d;
    e[0] = 0x2f8e9e;
    e[1] = 0x1c7f4b8;
    e[2] = 0x232e190;
    e[3] = 0x6cc2d;
    
    f = lambda v, i: (a[i] * v + b[i]) * c[i] + d[i] == e[i]
    inp = [0]*4
    for ii in range(4):
        for jj in range(65536):
            if f(jj, ii):
                inp[ii] = jj
                break


    return struct.pack("HHHH", *inp).hex()

sol5 = get_sol5()

tmp = [-47, 13, -53, 118, -102, 57, -55, 30, -77, 55, 64, -23, -37, -123, 126, -59, -15, -61, -52, -57, -114, -23, -122, 40, 103, -94, -52, 13, -20, -38, 36, -48]
sol6 = bytes([x % 256 for x in tmp]).hex() #pending

key = bytes.fromhex(sol1+sol2+sol3+sol4+sol5+sol6)

encFlag = [0]*0x3c
encFlag[0] = 199;
encFlag[1] = 0xc9;
encFlag[2] = 0x6e;
encFlag[3] = 0x78;
encFlag[4] = 0xe9;
encFlag[5] = 0x9b;
encFlag[6] = 0x85;
encFlag[7] = 0xf2;
encFlag[8] = 0x13;
encFlag[9] = 0x6d;
encFlag[10] = 0x32;
encFlag[11] = 0x33;
encFlag[12] = 0x40;
encFlag[13] = 0x3d;
encFlag[14] = 0xc;
encFlag[15] = 0xba;
encFlag[16] = 0x15;
encFlag[17] = 0xc1;
encFlag[18] = 0x1f;
encFlag[19] = 3;
encFlag[20] = 0x15;
encFlag[21] = 0xb1;
encFlag[22] = 0x68;
encFlag[23] = 0x45;
encFlag[24] = 0xd6;
encFlag[25] = 0xb3;
encFlag[26] = 0xee;
encFlag[27] = 0x69;
encFlag[28] = 0xd9;
encFlag[29] = 0xca;
encFlag[30] = 0x4a;
encFlag[31] = 0x2b;
encFlag[32] = 0x2c;
encFlag[33] = 0x6b;
encFlag[34] = 0xc;
encFlag[35] = 0xd6;
encFlag[36] = 0x9b;
encFlag[37] = 0x38;
encFlag[38] = 0x27;
encFlag[39] = 0xfa;
encFlag[40] = 0x3e;
encFlag[41] = 0xcd;
encFlag[42] = 0x4a;
encFlag[43] = 0x1f;
encFlag[44] = 0xcf;
encFlag[45] = 0xd7;
encFlag[46] = 0xe;
encFlag[47] = 0x36;
encFlag[48] = 0xfd;
encFlag[49] = 0xa7;
encFlag[50] = 0xc3;
encFlag[51] = 0x7b;
encFlag[52] = 0x69;
encFlag[53] = 0xb;
encFlag[54] = 0x57;
encFlag[55] = 0x3c;
encFlag[56] = 0xce;
encFlag[57] = 0xfa;
encFlag[58] = 0xef;
encFlag[59] = 0xff

from Crypto.Cipher import ARC4
rc4 = ARC4.new(key)

print(rc4.decrypt(bytes(encFlag)))
