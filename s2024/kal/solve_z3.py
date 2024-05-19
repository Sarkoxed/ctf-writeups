from z3 import Solver, BitVec, LShR, Or, sat


def get_dword(arr, offset):
    b0, b1, b2, b3 = arr[offset : offset + 4]
    return (
        denormalize(b0, 8)
        + 256 * denormalize(b1, 8)
        + 256**2 * denormalize(b2, 8)
        + 256**3 * denormalize(b3, 8)
    )


def get_short(arr, offset):
    b0, b1 = arr[offset : offset + 2]
    return denormalize(b0, 8) + 256 * denormalize(b1, 8)


def normalize(x, n):
    x &= 2**n - 1
    return (x ^ 2 ** (n - 1)) - 2 ** (n - 1)


def denormalize(x, n):
    return x & (2**n - 1)


def int32(x):
    if not isinstance(x, int):
        return x
    return normalize(x, 32)


def int16(x):
    return normalize(x, 16)


def int8(x):
    return normalize(x, 8)


def check1(ans, constr=False):
    # int v1 = (((int)ans[10] - (int)ans[4]) * 0x1000000 >> 0x18) + 0x5a;
    # return ((v1 >> 0x1f) - v1 ^ v1 >> 0x1f);

    v1 = int32(ans[10] - ans[4])
    v1 = int32(v1 * 0x1000000)
    v1 = int32(v1 >> 0x18)
    v1 = int32(v1 + 0x5A)

    ret1 = int32(v1 >> 0x1F)
    ret2 = int32(ret1 - v1)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v1 == 0


def check2(ans, constr=False):
    # int v2 = (char)(ans[6] + ans[0x1e] ^ ans[4] - (ans[0x1d] & ans[0x19])) + 0xb;
    # return ((v2 >> 0x1f) - v2 ^ v2 >> 0x1f);

    tmp1 = int8(ans[6] + ans[0x1E])
    tmp2 = ans[0x1D] & ans[0x19]
    tmp3 = int8(ans[4] - tmp2)
    tmp4 = int8(tmp1 ^ tmp3)
    v2 = int32(tmp4 + 0xB)  # ????????

    ret1 = int32(v2 >> 0x1F)
    ret2 = int32(ret1 - v2)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v2 == 0


def check3(ans, constr=False):  # тоже нормализация похуй 0
    # int v3 = ((get_dword(ans, 8) + get_dword(ans, 0) ^
    #         (get_dword(ans, 7) | get_dword(ans, 3))) +  0x56cb0106);
    # return ((v3 >> 0x1f) - (v3 ^ v3 >> 0x1f));

    t1 = int32(get_dword(ans, 8))
    t2 = int32(get_dword(ans, 0))
    t3 = int32(get_dword(ans, 7))
    t4 = int32(get_dword(ans, 3))

    tmp1 = int32(t1 + t2)
    tmp2 = int32(t3 | t4)
    tmp3 = int32(tmp1 ^ tmp2)

    v3 = int32(tmp3 + 0x56CB0106)

    ret1 = int32(v3 >> 0x1F)
    ret2 = int32(ret1 - v3)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v3 == 0


def check4(ans, constr=False):
    # int v4 =
    #   (get_dword(ans, 10) ^ get_dword(ans, 4) ^
    #    get_dword(ans, 0x11) & (get_dword(ans, 0x17) ^ get_dword(ans, 0x1c)));
    # return (int)((v4 + v4 + 0xd0d747cc & (int)(v4 + 0x686ba3e6) >> 0x1f) -
    #            (v4 + 0x686ba3e6));

    t1 = int32(get_dword(ans, 10))
    t2 = int32(get_dword(ans, 4))
    t3 = int32(get_dword(ans, 0x11))
    t4 = int32(get_dword(ans, 0x17))
    t5 = int32(get_dword(ans, 0x1C))

    tmp1 = int32(t4 ^ t5)
    tmp2 = int32(t3 & tmp1)
    tmp3 = int32(t1 ^ t2)
    v4 = int32(tmp2 ^ tmp3)

    ret1 = int32(v4 + v4 + 0xD0D747CC)
    ret2 = int32(v4 + 0x686BA3E6)
    ret3 = int32(ret2 >> 0x1F)
    ret4 = int32(ret1 & ret3)
    ret5 = int32(v4 + 0x686BA3E6)
    ret6 = int32(ret4 - ret5)

    if not constr:
        return ret6
    return ret6 >= 0  # THE ONLY POSITIVE но мне в целом кажется что и это ноль


def check5(ans, constr=False):
    # int v5 = (int)(short)(get_short(ans, 0xe) + get_short(ans, 0x1d) &
    #                     get_short(ans, 0x12) -
    #                         (get_short(ans, 0x13) | get_short(ans, 0x1a)));
    # return (int)(v5 - 0x2258U | 0x2258U - v5);

    t1 = get_short(ans, 0xE)
    t2 = get_short(ans, 0x1D)
    t3 = get_short(ans, 0x12)
    t4 = get_short(ans, 0x13)
    t5 = get_short(ans, 0x1A)

    tmp1 = int16(t4 | t5)
    tmp2 = int16(t1 + t2)
    tmp3 = int16(t3 - tmp1)
    v5 = int16(tmp2 & tmp3)

    ret1 = int32(v5 - 0x2258)
    ret2 = int32(0x2258 - v5)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check6(ans, constr=False):
    # int v6 = ((get_dword(ans, 0x13) ^ get_dword(ans, 0x12)) -
    #         (get_dword(ans, 0x18) + get_dword(ans, 0x11) &
    #          (get_dword(ans, 7) ^ get_dword(ans, 0x14))));
    # return (int)(((int)(v6 + -0x66d6ff0b) >> 0x1f) -
    #            (v6 + 0x992900f5 ^ (int)(v6 + -0x66d6ff0b) >> 0x1f));

    t1 = int32(get_dword(ans, 0x13))
    t2 = int32(get_dword(ans, 0x12))
    t3 = int32(get_dword(ans, 0x18))
    t4 = int32(get_dword(ans, 0x11))
    t5 = int32(get_dword(ans, 7))
    t6 = int32(get_dword(ans, 0x14))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t3 + t4)
    tmp3 = int32(t5 ^ t6)
    tmp4 = int32(tmp2 & tmp3)
    v6 = int32(tmp1 - tmp4 - 0x66D6FF0B)

    ret1 = int32(v6 >> 0x1F)
    ret2 = int32(ret1 - v6)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v6 == 0


def check7(ans, constr=False):
    # int v7 = (get_dword(ans, 0xd) & get_dword(ans, 0x12) & get_dword(ans, 0x16) &
    #         get_dword(ans, 0));
    # return (int)(v7 + 0xdfffff80 | 0x20000080 - v7);

    t1 = int32(get_dword(ans, 0xD))
    t2 = int32(get_dword(ans, 0x12))
    t3 = int32(get_dword(ans, 0x16))
    t4 = int32(get_dword(ans, 0))

    tmp1 = int32(t1 & t2)
    tmp2 = int32(tmp1 & t3)
    v7 = int32(tmp2 & t4)

    ret1 = int32(v7 - 0x20000080)
    ret2 = int32(0x20000080 - v7)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check8(ans, constr=False):
    # int v8 = ((get_dword(ans, 5) & get_dword(ans, 6)) + 0xccedf7f7);
    # return (int)(((int)v8 >> 0x1f) - v8 ^ (int)v8 >> 0x1f);

    t1 = int32(get_dword(ans, 5))
    t2 = int32(get_dword(ans, 6))

    tmp1 = int32(t1 & t2)
    v8 = int32(tmp1 + 0xCCEDF7F7)

    ret1 = int32(v8 >> 0x1F)
    ret2 = int32(ret1 - v8)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v8 == 0


def check9(ans, constr=False):
    # int v9 = (int)(short)(get_short(ans, 0xc) | get_short(ans, 0x11) |
    #                     get_short(ans, 0x11) | get_short(ans, 0x15));
    # return (int)(v9 + 0x3005U | -v9 - 0x3005U);

    t1 = int32(get_short(ans, 0xC))
    t2 = int32(get_short(ans, 0x11))
    t3 = int32(get_short(ans, 0x11))
    t4 = int32(get_short(ans, 0x15))

    tmp1 = int32(t1 | t2)
    tmp2 = int32(tmp1 | t3)
    v9 = int32(tmp2 | t4)

    ret1 = int32(v9 + 0x3005)
    ret2 = int32(-0x3005 - v9)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check10(ans, constr=False):
    # int v10 = (((int)(short)(get_short(ans, 0x1e) & get_short(ans, 6)) +
    #             (int)(short)(get_short(ans, 5) & get_short(ans, 0x1d))) *
    #                0x10000 >>
    #            0x10);
    # return (int)(v10 - 0x1018U | 0x1018U - v10);

    t1 = int16(get_short(ans, 0x1E))
    t2 = int16(get_short(ans, 6))
    t3 = int16(get_short(ans, 5))
    t4 = int16(get_short(ans, 0x1D))

    tmp1 = int32(t1 & t2)
    tmp2 = int32(t3 & t4)
    tmp3 = int32(tmp1 + tmp2)
    tmp4 = int32(tmp3 * 0x10000)
    v10 = int32(tmp4 >> 0x10)

    ret1 = int32(v10 - 0x1018)
    ret2 = int32(0x1018 - v10)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check11(ans, constr=False):
    # int v11 = (((int)(char)(ans[9] | ans[6]) +
    #           ((int)(char)(ans[0x1e] ^ ans[1]) &
    #            (int)(char)ans[4] - (int)(char)ans[0x1f])) *
    #              0x1000000 >>
    #          0x18);
    # return ((v11 + -7 >> 0x1f) - (v11 + -7) ^ v11 + -7 >> 0x1f);

    tmp1 = int32(ans[9] | ans[6])
    tmp2 = int32(ans[0x1E] ^ ans[1])
    tmp3 = int32(ans[4] - ans[0x1F])
    tmp4 = int32(tmp2 & tmp3)
    tmp5 = int32(tmp1 + tmp4)
    tmp6 = int32(tmp5 * 0x1000000)
    tmp7 = int32(tmp6 >> 0x18)
    v11 = int32(tmp7 - 7)

    ret1 = int32(v11 >> 0x1F)
    ret2 = int32(ret1 - v11)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v11 == 0


def check12(ans, constr=False):
    # int v12 = ((((int)(char)ans[10] - (int)(char)ans[0x17]) +
    #           ((int)(char)ans[0x19] - (int)(char)ans[0x14]) +
    #           (int)(char)(ans[2] & ans[0xb])) *
    #              0x1000000 >>
    #          0x18);
    # return ((v12 + 0xb >> 0x1f) - (v12 + 0xb) ^ v12 + 0xb >> 0x1f);

    tmp1 = int32(ans[10] - ans[0x17])
    tmp2 = int32(ans[0x19] - ans[0x14])
    tmp3 = int32(ans[2] & ans[0xB])
    tmp4 = int32(tmp1 + tmp2 + tmp3)
    tmp5 = int32(tmp4 * 0x1000000)
    tmp6 = int32(tmp5 >> 0x18)
    v12 = int32(tmp6 + 0xB)

    ret1 = int32(v12 >> 0x1F)
    ret2 = int32(ret1 - v12)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v12 == 0


def check13(ans, constr=False):
    # int v13 = (int)(short)(get_short(ans, 0) | get_short(ans, 0xc) |
    #                      get_short(ans, 0xb));
    # return (int)(v13 + 0x2005U | -v13 - 0x2005U);

    t1 = int16(get_short(ans, 0))
    t2 = int16(get_short(ans, 0xC))
    t3 = int16(get_short(ans, 0xB))

    v13 = int16(t1 | t2 | t3)

    ret1 = int32(v13 + 0x2005)
    ret2 = int32(-0x2005 - v13)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check14(ans, constr=False):
    # int v14 = (get_dword(ans, 0x10) ^ get_dword(ans, 0x1c));
    # return (int)(v14 + 0xe817e6e3 | 0x17e8191d - v14);

    t1 = int16(get_dword(ans, 0x10))
    t2 = int16(get_dword(ans, 0x1C))

    v14 = int32(t1 ^ t2)

    ret1 = int32(v14 + 0xE817E6E3)
    ret2 = int32(0x17E8191D - v14)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check15(ans, constr=False):
    # int v15 = (((int)(char)(ans[0x17] ^ *ans) -
    #             (((int)(char)ans[0x17] + (int)(char)ans[0x15]) -
    #              ((int)(char)ans[0x14] + (int)(char)ans[0x19]))) *
    #                0x1000000 >>
    #            0x18);
    # return (int)(v15 - 0x18U | 0x18U - v15);

    tmp1 = int32(ans[0x17] ^ ans[0])
    tmp2 = int32(ans[0x17] + ans[0x15])
    tmp3 = int32(ans[0x14] + ans[0x19])
    tmp4 = int32(tmp2 - tmp3)
    tmp5 = int32(tmp1 - tmp4)
    tmp6 = int32(tmp5 * 0x1000000)
    v15 = int32(tmp6 >> 0x18)

    ret1 = int32(v15 - 0x18)
    ret2 = int32(0x18 - v15)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check16(ans, constr=False):
    # int v16 = ((((int)get_short(ans, 0x18) - (int)get_short(ans, 0x16)) +
    #           ((int)get_short(ans, 0) |
    #            (int)get_short(ans, 6) + (int)get_short(ans, 0xf))) *
    #              0x10000 >>
    #          0x10);
    # return (int)(v16 + 0x6840U | -v16 - 0x6840U);

    t1 = int32(get_short(ans, 0x18))
    t2 = int32(get_short(ans, 0x16))
    t3 = int32(get_short(ans, 0))
    t4 = int32(get_short(ans, 6))
    t5 = int32(get_short(ans, 0xF))

    tmp1 = int32(t1 - t2)
    tmp2 = int32(t4 + t5)
    tmp3 = int32(t3 | tmp2)
    tmp4 = int32(tmp1 + tmp3)
    tmp5 = int32(tmp4 * 0x10000)
    v16 = int32(tmp5 >> 0x10)

    ret1 = int32(v16 + 0x6840)
    ret2 = int32(-0x6840 - v16)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check17(ans, constr=False):
    # int v17 =
    #    (((int)(char)ans[3] - ((int)(char)ans[0x1e] - (int)(char)ans[0x1e])) *
    #         0x1000000 >>
    #     0x18);
    # return (int)(v17 - 0x76U | 0x76U - v17);

    tmp1 = int32(ans[0x1E] - ans[0x1E])
    tmp2 = int32(ans[3] - tmp1)
    tmp3 = int32(tmp2 * 0x1000000)
    v17 = int32(tmp3 >> 0x18)

    ret1 = int32(v17 - 0x76)
    ret2 = int32(0x76 - v17)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check18(ans, constr=False):

    t1 = int32(get_dword(ans, 0x1B))
    t2 = int32(get_dword(ans, 0x14))
    t3 = int32(get_dword(ans, 0x11))
    t4 = int32(get_dword(ans, 0xC))
    t5 = int32(get_dword(ans, 0x1B))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t3 | t4 | t5)
    v18 = int32(tmp1 - tmp2)

    ret1 = int32(v18 + 0xE3A3E85C)
    ret2 = int32(0x1C5C17A4 - v18)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check19(ans, constr=False):

    tmp1 = int32(ans[0x16] + ans[0x16])
    tmp2 = int32(tmp1 * 0x1000000)
    v19 = int32(tmp2 >> 0x18)

    ret1 = int32(v19 + v19 - 0x18)
    ret2 = int32(v19 - 0xC)
    ret3 = int32(ret2 >> 0x1F)
    ret4 = int32(ret1 & ret3)
    ret5 = int32(v19 - 0xC)
    ret6 = int32(ret4 - ret5)

    if not constr:
        return ret6
    return ret6 >= 0  # THE ONLY POSITIVE но мне в целом кажется что и это ноль


def check20(ans, constr=False):

    t1 = int16(get_short(ans, 7))
    t2 = int16(get_short(ans, 0x14))
    t3 = int16(get_short(ans, 0xC))
    t4 = int16(get_short(ans, 0xF))
    t5 = int16(get_short(ans, 0x1B))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t1 + t3)
    tmp3 = int32(t4 | t5)
    tmp4 = int32(tmp2 & tmp3)
    tmp5 = int32(tmp1 - tmp4)
    tmp6 = int32(tmp5 * 0x10000)
    tmp7 = int32(tmp6 >> 0x10)
    v20 = int32(tmp7 - 0x21C7)

    ret1 = int32(v20 >> 0x1F)
    ret2 = int32(ret1 - v20)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v20 == 0


def check21(ans, constr=False):
    t1 = int32(get_dword(ans, 3))
    t2 = int32(get_dword(ans, 3))

    v21 = int32(t1 ^ t2)

    ret1 = int32(v21 >> 0x1F)
    ret2 = int32(ret1 - v21)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v21 == 0


def check22(ans, constr=False):
    t1 = int32(get_dword(ans, 9))
    t2 = int32(get_dword(ans, 3))
    t3 = int32(get_dword(ans, 0x17))

    tmp1 = int32(t2 ^ t3)
    v22 = int32(t1 | tmp1)

    ret1 = int32(v22 + 0x20040281)
    ret2 = int32(0xDFFBFD7F - v22)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check23(ans, constr=False):

    tmp1 = int32(ans[0x13] ^ ans[4])
    tmp2 = int32(ans[2] ^ ans[0x11])
    tmp3 = int32(tmp2 | ans[0x1D])
    tmp4 = int32(tmp1 - tmp3)
    tmp5 = int32(tmp4 * 0x1000000)
    v23 = int32(tmp5 >> 0x18)

    ret1 = int32(v23 + 0x7D)
    ret2 = int32(-0x7D - v23)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check24(ans, constr=False):
    t1 = int16(get_short(ans, 1))
    t2 = int16(get_short(ans, 10))
    t3 = int16(get_short(ans, 2))

    tmp1 = int16(t2 & t3)
    v24 = int16(t1 ^ tmp1)

    ret1 = int32(v24 + v24 + 0xA966)
    ret2 = int32(v24 + 0x54B3)
    ret3 = int32(ret2 >> 0x1F)
    ret4 = int32(ret1 & ret3)
    ret5 = int32(v24 + 0x54B3)
    ret6 = int32(ret4 - ret5)

    if not constr:
        return ret6
    return ret6 >= 0  # THE ONLY POSITIVE но мне в целом кажется что и это ноль


def check25(ans, constr=False):

    t1 = int16(get_short(ans, 0xD))
    t2 = int16(get_short(ans, 0xC))
    t3 = int16(get_short(ans, 0x10))
    t4 = int16(get_short(ans, 0xE))
    t5 = int16(get_short(ans, 0x1E))

    tmp1 = int32(t1 - t2)
    tmp2 = int32(t4 | t5)
    tmp3 = int32(t3 & tmp2)
    tmp4 = int32(tmp1 + tmp3)
    tmp5 = int32(tmp4 * 0x10000)
    tmp6 = int32(tmp5 >> 0x10)
    v25 = int32(tmp6 + 0x45E6)

    ret1 = int32(v25 >> 0x1F)
    ret2 = int32(ret1 - v25)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v25 == 0


def check26(ans, constr=False):
    tmp1 = int32(ans[0x1E] | ans[0x18])
    tmp2 = int32(ans[0x17] + tmp1)
    tmp3 = int32(tmp2 * 0x1000000)
    v26 = int32(tmp3 >> 0x18)

    ret1 = int32(v26 + 0x71)
    ret2 = int32(-0x71 - v26)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check27(ans, constr=False):
    t1 = int16(get_short(ans, 0x15))
    t2 = int16(get_short(ans, 0x10))
    t3 = int16(get_short(ans, 4))
    t4 = int16(get_short(ans, 0x17))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t3 - t4)
    tmp3 = int32(tmp1 - tmp2)
    tmp4 = int32(tmp3 * 0x10000)
    v27 = int32(tmp4 >> 0x10)

    ret1 = int32(v27 - 0x72A6)
    ret2 = int32(0x72A6 - v27)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check28(ans, constr=False):
    t1 = int16(get_short(ans, 0x12))
    t2 = int16(get_short(ans, 0x11))

    tmp1 = int16(t1 | t2)
    v28 = int32(tmp1 + 0x3031)

    ret1 = int32(v28 >> 0x1F)
    ret2 = int32(ret1 - v28)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v28 == 0


def check29(ans, constr=False):
    t1 = int16(get_short(ans, 0x14))
    t2 = int16(get_short(ans, 0xC))
    v29 = int16(t1 | t2)

    ret1 = int32(v29 + v29 + 0x2442)
    ret2 = int32(v29 + 0x1221)
    ret3 = int32(ret2 >> 0x1F)
    ret4 = int32(ret1 & ret3)
    ret5 = int32(v29 + 0x1221)
    ret6 = int32(ret4 - ret5)

    if not constr:
        return ret6
    return ret6 >= 0  # THE ONLY POSITIVE но мне в целом кажется что и это ноль


def check30(ans, constr=False):
    t1 = int16(get_short(ans, 7))
    t2 = int16(get_short(ans, 8))
    t3 = int16(get_short(ans, 2))
    t4 = int16(get_short(ans, 10))

    tmp1 = int16(t3 ^ t4)
    tmp2 = int16(t2 - tmp1)
    tmp3 = int16(t1 | t2)
    v30 = int32(tmp3 | tmp2)

    ret1 = int32(v30 + 0x4041)
    ret2 = int32(-0x4041 - v30)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check31(ans, constr=False):
    t1 = int32(get_dword(ans, 7))
    t2 = int32(get_dword(ans, 0xD))
    t3 = int32(get_dword(ans, 0x10))
    t4 = int32(get_dword(ans, 0x16))
    t5 = int32(get_dword(ans, 0))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t3 + t4 + t5)
    tmp3 = int32(tmp1 & tmp2)
    v31 = int32(tmp3 + 0x5F0D37F8)

    ret1 = int32(v31 + v31)
    ret2 = int32(v31 >> 0x1F)
    ret3 = int32(ret1 & ret2)
    ret4 = int32(ret3 - v31)

    if not constr:
        return ret4
    return ret4 >= 0


def check32(ans, constr=False):
    t1 = int32(get_dword(ans, 0x17))
    t2 = int32(get_dword(ans, 0))

    tmp1 = int32(t1 & t2)
    v32 = int32(tmp1 + 0xBB7DFB00)

    ret1 = int32(v32 >> 0x1F)
    ret2 = int32(ret1 - v32)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v32 == 0


def check33(ans, constr=False):
    t1 = int16(get_short(ans, 7))
    t2 = int16(get_short(ans, 0xF))
    t3 = int16(get_short(ans, 0x1E))
    t4 = int16(get_short(ans, 4))
    t5 = int16(get_short(ans, 0x1C))
    t6 = int16(get_short(ans, 3))

    tmp1 = int16(t1 - t2)
    tmp2 = int16(t3 | t4)
    tmp3 = int16(t5 - t6)
    tmp4 = int16(tmp2 - tmp3)
    tmp5 = int16(tmp1 ^ tmp4)
    v33 = int32(tmp5 - 0x7811)

    ret1 = int32(v33 >> 0x1F)
    ret2 = int32(ret1 - v33)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v33 == 0


def check34(ans, constr=False):
    tmp1 = int32(ans[0x1F] | ans[0x1E])
    tmp2 = int32(ans[0x14] ^ ans[7])
    tmp3 = int32(ans[1] - ans[0])
    tmp4 = int32(tmp2 & tmp3)
    tmp5 = int32(tmp1 - tmp4)
    tmp6 = int32(tmp5 * 0x1000000)
    tmp7 = int32(tmp6 >> 0x18)
    v34 = int32(tmp7 + 0x1C)

    ret1 = int32(v34 >> 0x1F)
    ret2 = int32(ret1 - v34)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v34 == 0


def check35(ans, constr=False):
    tmp1 = int32(ans[0xC] & ans[4])
    tmp2 = int32(ans[0x10] - tmp1)
    tmp3 = int32(tmp2 * 0x1000000)
    tmp4 = int32(tmp3 >> 0x18)
    v35 = int32(tmp4 - 0x57)

    ret1 = int32(v35 >> 0x1F)
    ret2 = int32(ret1 - v35)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v35 == 0


def check36(ans, constr=False):
    tmp1 = int8(ans[0xB] + ans[0x12])
    tmp2 = int8(ans[8] + ans[7])
    tmp3 = int8(tmp2 ^ ans[0x1A] ^ ans[0x1C])
    v36 = int8(tmp1 | tmp3)

    ret1 = int32(v36 + 0xB)
    ret2 = int32(-0xB - v36)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check37(ans, constr=False):
    tmp1 = int32(ans[0xF] - ans[2])
    tmp2 = int32(tmp1 * 0x1000000)
    v37 = int32(tmp2 >> 0x18)

    ret1 = int32(v37 + 6)
    ret2 = int32(-6 - v37)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check38(ans, constr=False):
    t1 = int32(get_dword(ans, 0x1C))
    t2 = int32(get_dword(ans, 0xF))
    t3 = int32(get_dword(ans, 0x11))

    tmp1 = int32(t1 - t2)
    tmp2 = int32(t2 & t3)
    v38 = int32(tmp1 - tmp2)

    ret1 = int32(v38 + 0x8962D79A)
    ret2 = int32(0x769D2866 - v38)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check39(ans, constr=False):
    t1 = int32(get_dword(ans, 2))
    t2 = int32(get_dword(ans, 3))
    t3 = int32(get_dword(ans, 1))

    tmp1 = int32(t2 & t3)
    tmp2 = int32(t1 ^ tmp1)
    v39 = int32(tmp2 + 0x4E550331)

    ret1 = int32(v39 >> 0x1F)
    ret2 = int32(ret1 - v39)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v39 == 0


def check40(ans, constr=False):
    tmp1 = int32(ans[0x14] & ans[0x12])
    tmp2 = int32(ans[0xB] ^ ans[6] ^ ans[9] ^ ans[0x11])
    tmp3 = int32(tmp1 + tmp2)
    tmp4 = int32(tmp3 * 0x1000000)
    v40 = int32(tmp4 >> 0x18)

    ret1 = int32(v40 - 0x60)
    ret2 = int32(0x60 - v40)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check41(ans, constr=False):
    v41 = int32(ans[3] & ans[0x14] & ans[0xB])

    if not isinstance(v41, int):
        ret1 = int32(LShR(v41, 1) - v41)
    else:
        ret1 = int32((denormalize(v41, 32) >> 1) - v41)

    if not constr:
        return ret1
    return ret1 >= 0  # вроде тут тоже 0


def check42(ans, constr=False):
    t1 = int32(get_dword(ans, 2))
    t2 = int32(get_dword(ans, 9))
    t3 = int32(get_dword(ans, 0xE))

    tmp1 = int32(t2 - t3)
    tmp2 = int32(t1 - tmp1)
    v42 = int32(tmp2 - 0x21A2FC12)

    ret1 = int32(v42 >> 0x1F)
    ret2 = int32(ret1 - v42)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v42 == 0


def check43(ans, constr=False):
    t1 = int16(get_short(ans, 0x1B))
    t2 = int16(get_short(ans, 0x17))
    t3 = int16(get_short(ans, 0x12))

    tmp1 = int16(t2 & t3)
    tmp2 = int16(t1 | t1 | t2 | tmp1)
    v43 = int32(tmp2 + 0x10D3)

    ret1 = int32(v43 + v43)
    ret2 = int32(v43 >> 0x1F)
    ret3 = int32(ret1 & ret2)
    ret4 = int32(ret3 - v43)

    if not constr:
        return ret4
    return ret4 >= 0


def check44(ans, constr=False):
    t1 = int32(get_dword(ans, 0xB))
    t2 = int32(get_dword(ans, 4))
    t3 = int32(get_dword(ans, 7))

    tmp1 = int32(t2 - t3)
    tmp2 = int32(t1 ^ tmp1)
    v44 = int32(tmp2 + 0x5FEBA26B)

    ret1 = int32(v44 + v44)
    ret2 = int32(v44 >> 0x1F)
    ret3 = int32(ret1 & ret2)
    ret4 = int32(ret3 - v44)

    if not constr:
        return ret4
    return ret4 >= 0


def check45(ans, constr=False):
    t1 = int32(get_dword(ans, 2))
    t2 = int32(get_dword(ans, 0xB))
    t3 = int32(get_dword(ans, 6))
    t4 = int32(get_dword(ans, 9))

    tmp1 = int32(t1 - t2)
    tmp2 = int32(t3 ^ t4)
    v45 = tmp1 & tmp2

    ret1 = int32(v45 + 0x57EFE51E)
    ret2 = int32(0xA8101AE2 - v45)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check46(ans, constr=False):
    t1 = int32(get_dword(ans, 0x1A))
    t2 = int32(get_dword(ans, 4))
    t3 = int32(get_dword(ans, 5))
    t4 = int32(get_dword(ans, 0x12))
    t5 = int32(get_dword(ans, 0x1B))
    t6 = int32(get_dword(ans, 0xE))

    tmp1 = int32(t1 & t2)
    tmp2 = int32(t3 ^ t4 ^ t5 ^ t6)
    v46 = int32(tmp1 | tmp2)

    ret1 = int32(v46 + v46 + 0x8009A0E4)
    ret2 = int32(v46 + 0x4004D072)
    ret3 = int32(ret2 >> 0x1F)
    ret4 = int32(ret1 & ret3)
    ret5 = int32(v46 + 0x4004D072)
    ret6 = int32(ret4 - ret5)

    if not constr:
        return ret6
    return ret6 >= 0  # THE ONLY POSITIVE но мне в целом кажется что и это ноль


def check47(ans, constr=False):
    t1 = int32(get_dword(ans, 1))
    t2 = int32(get_dword(ans, 6))
    t3 = int32(get_dword(ans, 0xD))
    t4 = int32(get_dword(ans, 0x1C))

    tmp1 = int32(t1 + t2)
    tmp2 = int32(t4 + t4)
    v47 = int32(tmp1 & tmp2 & t3)

    ret1 = int32(v47 + 0x7FFEDF80)
    ret2 = int32(0x80012080 - v47)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check48(ans, constr=False):
    t1 = int16(get_short(ans, 0x1E))
    t2 = int16(get_short(ans, 0x10))
    t3 = int16(get_short(ans, 1))
    t4 = int16(get_short(ans, 0xB))
    t5 = int16(get_short(ans, 2))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t4 + t5)
    tmp3 = int32(t3 & tmp2)
    tmp4 = int32(tmp1 + tmp3)
    tmp5 = int32(tmp4 * 0x10000)
    tmp6 = int32(tmp5 >> 0x10)
    v48 = int32(tmp6 - 0x55D9)

    ret1 = int32(v48 >> 0x1F)
    ret2 = int32(ret1 - v48)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v48 == 0


def check49(ans, constr=False):
    t1 = int16(get_short(ans, 0x13))
    t2 = int16(get_short(ans, 0x18))
    t3 = int16(get_short(ans, 6))

    tmp1 = int16(t2 + t3)
    tmp2 = int16(t1 | tmp1)
    v49 = int32(tmp2 + 0x3009)

    ret1 = int32(v49 + v49)
    ret2 = int32(v49 >> 0x1F)
    ret3 = int32(ret1 & ret2)
    ret4 = int32(ret3 - v49)

    if not constr:
        return ret4
    return ret4 >= 0


def check50(ans, constr=False):
    t1 = int16(get_short(ans, 0x15))
    t2 = int16(get_short(ans, 2))
    t3 = int16(get_short(ans, 0x1C))
    t4 = int16(get_short(ans, 0x13))
    t5 = int16(get_short(ans, 4))
    t6 = int16(get_short(ans, 0x12))

    tmp1 = int16(t3 | t4)
    tmp2 = int16(tmp1 - (t5 & t6))
    tmp3 = int16(t1 & t2)
    tmp4 = int16(tmp3 | tmp2)
    v50 = int32(tmp4 + 0x2011)

    ret1 = int32(v50 >> 0x1F)
    ret2 = int32(ret1 - v50)
    ret3 = int32(ret2 ^ ret1)

    if not constr:
        return ret3
    return v50 == 0


def check51(ans, constr=False):
    t1 = int16(get_short(ans, 0x13))
    t2 = int16(get_short(ans, 0x14))
    t3 = int16(get_short(ans, 0x16))

    tmp1 = int32(t1 ^ t2)
    tmp2 = int32(t2 - t3)
    tmp3 = int32(tmp1 - tmp2)
    tmp4 = int32(tmp3 * 0x10000)
    v51 = int32(tmp4 >> 0x10)

    ret1 = int32(v51 + v51 + 0xB37E)
    ret2 = int32(v51 + 0x59BF)
    ret3 = int32(ret2 >> 0x1F)
    ret4 = int32(ret1 & ret3)
    ret5 = int32(v51 + 0x59BF)
    ret6 = int32(ret4 - ret5)

    if not constr:
        return ret6
    return ret6 >= 0  # THE ONLY POSITIVE но мне в целом кажется что и это ноль


def check52(ans, constr=False):
    t1 = int16(get_short(ans, 1))
    t2 = int16(get_short(ans, 0x12))
    t3 = int16(get_short(ans, 0x1E))
    t4 = int16(get_short(ans, 0x1C))

    tmp1 = int16(t1 & t2)
    v52 = int32(tmp1 ^ t3 ^ t4)

    ret1 = int32(v52 + 0x363C)
    ret2 = int32(-0x363C - v52)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


def check53(ans, constr=False):
    tmp1 = int32(ans[0] | ans[0x14])
    v53 = int32(tmp1 & ans[0x1F])

    ret1 = int32(v53 + 0x30)
    ret2 = int32(-0x30 - v53)
    ret3 = int32(ret1 | ret2)

    if not constr:
        return ret3
    return ret1 == 0


if __name__ == "__main__":
    s = Solver()
    ans = [BitVec(f"ans_{i}", 32) for i in range(32)]
    ans1 = [int8(x) for x in ans]

    s.add(check1(ans1, True))
    s.add(check2(ans1, True))
    s.add(check3(ans1, True))
    s.add(check4(ans1, True))
    s.add(check5(ans1, True))
    s.add(check6(ans1, True))
    s.add(check7(ans1, True))
    s.add(check8(ans1, True))  # ???  9 стало 0...
    # s.add(check9(ans1, True))
    s.add(check10(ans1, True))
    s.add(check11(ans1, True))
    s.add(check12(ans1, True))
    s.add(check13(ans1, True))
    # s.add(check14(ans1, True))
    s.add(check15(ans1, True))
    s.add(check16(ans1, True))
    s.add(check17(ans1, True))
    s.add(check18(ans1, True))
    s.add(check19(ans1, True))
    s.add(check20(ans1, True))
    s.add(check21(ans1, True))
    s.add(check22(ans1, True))
    s.add(check23(ans1, True))
    s.add(check24(ans1, True))
    s.add(check25(ans1, True))
    s.add(check26(ans1, True))
    s.add(check27(ans1, True))
    s.add(check28(ans1, True))
    s.add(check29(ans1, True))
    s.add(check30(ans1, True))
    s.add(check31(ans1, True))
    s.add(check32(ans1, True))
    s.add(check33(ans1, True))
    s.add(check34(ans1, True))
    s.add(check35(ans1, True))
    s.add(check36(ans1, True))
    s.add(check37(ans1, True))
    s.add(check38(ans1, True))
    s.add(check39(ans1, True))
    s.add(check40(ans1, True))
    s.add(check41(ans1, True))
    s.add(check42(ans1, True))
    s.add(check43(ans1, True))
    s.add(check44(ans1, True))
    s.add(check45(ans1, True))
    s.add(check46(ans1, True))
    s.add(check47(ans1, True))
    s.add(check48(ans1, True))
    s.add(check49(ans1, True))
    s.add(check50(ans1, True))
    s.add(check51(ans1, True))
    s.add(check52(ans1, True))
    s.add(check53(ans1, True))

    print(s.check())
    while s.check() == sat:
        m = s.model()
        values = [int8(m[x].as_long()) for x in ans]
        print(values)

        new_cond = []
        for x, y in zip(values, ans1):
            new_cond.append(x != int8(y))
        s.add(Or(new_cond))
