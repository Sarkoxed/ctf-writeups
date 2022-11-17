---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.14.1
  kernelspec:
    display_name: Python 3 (ipykernel)
    language: python
    name: python3
---

# Chaffymasking
Note: Solution is unintended

## Description
<pre>Chaffy masking is a popular cryptography technique that is used to protect cryptographic implementations against several attacks
nc 65.21.255.31 31377</pre>
<b>Attachments in repo</b>

## Solution
Well, the key to my solution is that <b>salt check</b> is weak, since I am able to control the whole vector, hence no random padding included. Thus the whole protocol becomes very symmetric.

```python
import numpy as np
```

These are the functions from the task sources, with the exception of <b>chaffy_mask</b>, which I barely changed, only used the input as a flag.

```python
def pad(inp, length):
    result = inp + os.urandom(length - len(inp))
    return result


def byte_xor(a, b):
    return bytes(_a ^ _b for _a, _b in zip(a, b))


def chaffy_mask(masked_fl, salt, LTC, m, n):
    q = n**2
    half1_salt = salt[: m // 8]
    half2_salt = salt[m // 8 :]
    
    half1_binStr = "{:08b}".format(int(half1_salt.hex(), 16))
    half2_binStr = "{:08b}".format(int(half2_salt.hex(), 16))

    vec_1 = np.array(list(half1_binStr), dtype=int)
    vec_1 = np.reshape(vec_1, (m, 1))
    vec_2 = np.array(list(half2_binStr), dtype=int)
    vec_2 = np.reshape(vec_2, (m, 1))

    out_1 = LTC.dot(vec_1) % q
    out_2 = LTC.dot(vec_2) % q

    flag_vector = np.array([i for i in masked_fl])
    flag_vector = np.reshape(flag_vector, (n, 1))
    masked_flag = (flag_vector ^ out_1 ^ out_2) % 256
    masked_flag = np.reshape(masked_flag, (n,))
    masked_flag = "".join([hex(_)[2:].zfill(2) for _ in masked_flag])
    return bytes.fromhex(masked_flag)
```

```python
m, n = 512, 64
IVK = [3826, 476, 3667, 2233, 1239, 1166, 2119, 2559, 2376, 1208, 2165, 2897, 830, 529, 346, 150, 2188, 4025, 3667, 1829, 3987, 952, 3860, 2574, 959, 1394, 1481, 2822, 3794, 2950, 1190, 777, 604, 82, 49, 710, 1765, 3752, 2970, 952, 803, 873, 2647, 2643, 1096, 1202, 2236, 1492, 3372, 2106, 1868, 535, 161, 3143, 3370, 1, 1643, 2147, 2368, 3961, 1339, 552, 2641, 3222, 2505, 3449, 1540, 2024, 618, 1904, 314, 1306, 3173, 4040, 1488, 1339, 2545, 2167, 394, 46, 3169, 897, 4085, 4067, 3461, 3444, 118, 3185, 2267, 3239, 3612, 2775, 580, 3579, 3623, 1721, 189, 650, 2755, 1434, 35, 3167, 323, 589, 3410, 652, 2746, 2787, 3665, 828, 3200, 1450, 3147, 720, 3741, 1055, 505, 2929, 1423, 3629, 3, 1269, 4066, 125, 2432, 3306, 4015, 2350, 2154, 2623, 1304, 493, 763, 1765, 2608, 695, 30, 2462, 294, 3656, 3231, 3647, 3776, 3457, 2285, 2992, 3997, 603, 2342, 2283, 3029, 3299, 1690, 3281, 3568, 1927, 2909, 1797, 1675, 3245, 2604, 1272, 1146, 3301, 13, 3712, 2691, 1097, 1396, 3694, 3866, 2066, 1946, 3476, 1182, 3409, 3510, 2920, 2743, 1126, 2154, 3447, 1442, 2021, 1748, 1075, 1439, 3932, 3438, 781, 1478, 1708, 461, 50, 1881, 1353, 2959, 1225, 1923, 1414, 4046, 3416, 2845, 1498, 4036, 3899, 3878, 766, 3975, 1355, 2602, 3588, 3508, 3660, 3237, 3018, 1619, 2797, 1823, 1185, 3225, 1270, 87, 979, 124, 1239, 1763, 2672, 3951, 984, 869, 3897, 327, 912, 1826, 3354, 1485, 2942, 746, 833, 3968, 1437, 3590, 2151, 1523, 98, 164, 3119, 1161, 3804, 1850, 3027, 1715, 3847, 2407, 2549, 467, 2029, 2808, 1782, 1134, 1953, 47, 1406, 3828, 1277, 2864, 2392, 3458, 2877, 1851, 1033, 798, 2187, 54, 2800, 890, 3759, 4085, 3801, 3128, 3788, 2926, 1983, 55, 2173, 2579, 904, 1019, 2108, 3054, 284, 2428, 2371, 2045, 907, 1379, 2367, 351, 3678, 1087, 2821, 152, 1783, 1993, 3183, 1317, 2726, 2609, 1255, 144, 2415, 2498, 721, 668, 355, 94, 1997, 2609, 1945, 3011, 2405, 713, 2811, 4076, 2367, 3218, 1353, 3957, 2056, 881, 3420, 1994, 1329, 892, 1577, 688, 134, 371, 774, 3855, 1461, 1536, 1824, 1164, 1675, 46, 1267, 3652, 67, 3816, 3169, 2116, 3930, 2979, 3166, 3944, 2252, 2988, 34, 873, 1643, 1159, 2822, 1235, 2604, 888, 2036, 3053, 971, 1585, 2439, 2599, 1447, 1773, 984, 261, 3233, 2861, 618, 465, 3016, 3081, 1230, 1027, 3177, 459, 3041, 513, 1505, 3410, 3167, 177, 958, 2118, 326, 31, 2663, 2026, 2549, 3026, 2364, 1540, 3236, 2644, 4050, 735, 280, 798, 169, 3808, 2384, 3497, 1759, 2415, 3444, 1562, 3472, 1151, 1984, 2454, 3167, 1538, 941, 1561, 3071, 845, 2824, 58, 1467, 3807, 2191, 1858, 106, 3847, 1326, 3868, 2787, 1624, 795, 3214, 1932, 3496, 457, 2595, 3043, 772, 2436, 2160, 3428, 2005, 2597, 1932, 101, 3528, 1698, 3663, 900, 3298, 1872, 1179, 3987, 3695, 3561, 1762, 3785, 3005, 2574, 6, 1524, 2738, 1753, 2350, 558, 800, 3782, 722, 886, 2176, 3050, 221, 1925, 564, 1271, 2535, 3113, 1310, 2098, 3011, 964, 3281, 6, 1326, 741, 189, 2632, 373, 1176, 548, 64, 1445, 2376, 1524, 2690, 1316, 2304, 1336, 2257, 3227, 2542, 3911, 3460]

LTC = np.zeros([n, m], dtype=(int))
LTC[0, :] = IVK

for i in range(1, n):
    for j in range(m // n + 1):
        LTC[i, j * n : (j + 1) * n] = np.roll(IVK[j * n : (j + 1) * n], i)
```

```python
import re
from pwn import remote
from Crypto.Util.number import long_to_bytes, bytes_to_long

r = remote("65.21.255.31", 31377)

salt = long_to_bytes(int('1' + '0' * 511 + '1' + '0' * 510 + '1', 2))  # there might be any input you want, 
                                                               # since it's length is exactly 128 in binary
r.recvuntil(b"Give me your salt:")
r.sendline(salt)

mes = r.recvuntil(b"Give me your salt").decode()
masked_flag = eval(re.findall(r'b\'[a-z\d]+\'', mes)[0]).decode()
print(masked_flag)
r.close()
```

```python
chaffy_mask(bytes.fromhex(masked_flag), salt, LTC, m, n)
```
