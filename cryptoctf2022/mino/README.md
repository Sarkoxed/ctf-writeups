<h>Task:</h>
<br>
```
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Hi crypto programmers! I'm looking for some very special permutation |
| p name MINO such that sum(p(i) * (-2)^i) = 0 from 0 to n - 1, for    |
| example for n = 6, the permutation p = (4, 2, 6, 5, 3, 1) is MINO:   |
| 4*(-2)^0 + 2*(-2)^1 + 6*(-2)^2 + 5*(-2)^3 + 3*(-2)^4 + 1*(-2)^5 = 0  |
| In each step find such permutation and send to server, if there is   |
| NOT such permutation for given n, just send `TINP', good luck :)     |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Send a MINO permutation of length = 3 separated by comma:
```

<p>We have an equation:</p>
<code>a1 * (-2)**0 + a2 * (-2)**1  + a3 * (-2)**2 + a4 * (-2)**3 + ... + an * (-2)**(n-1) = f(n) = 0</code>
<br><code>Where ai in [1, n]</code><br>
<p>Let's check this very equation modulo 2:</p>
<code>a1 = 0 (mod 2) => a1 = 2 * k1, where k1 in [1, n//2]</code>
<p>Modulo 4:</p>
<code>a1 - 2 * a2 = 0 (mod 4) => 2 * k1 - 2 * a2 = 0 (mod 4) => a2 = k1 (mod 2) => a2 = k1 + 2 * k2</code>
<p>Modulo 8:</p>
<code>a1 - 2 * a2 + 4 * a3 = 0 (mod 8) => 2 * k1 - 2 * k1 - 4 * k2 + 4 * a3 = 0 (mod 8) => a3 = k2 (mod 8) => a3 = k2 + 2 * k3</code>
<p>And so on until 2**(n-1)</p>
<code> a(n-1) = k(n-2) + 2 * k(n-1) </code><br>
<code> an = k(n-1) (no modulo due to the condition of the problem)</code>
<p>Thus we have this system of equations:</p>
<code> a1 = 2 * k1 </code><br>
<code> a2 = k1 + 2 * k2 </code><br>
<code> a3 = k2 + 2 * k3 </code><br>
<code> a4 = k3 + 2 * k4 </code><br>
<code> a5 = k4 + 2 * k5 </code><br>
<code> ... </code><br>
<code> a(n-2) = k(n-3) + 2 * k(n-2) </code><br>
<code> a(n-1) = k(n-2) + 2 * k(n-1) </code><br>
<code> an = k(n-1)</code><br>
<p>If you sum all this equation up, you will get:</p>
<code> a1 + a2 + ... + an = 3 * (k1 + k2 + ... + k(n-1)), where a1 + a2 + ... + an = n * (n + 1) / 2 as the sum of n successive numbers(the order does not matter)</code>
<p>Hence we can conclude, that the existance of a solution is based on divisibility of the sum by 3</p>
    
    
<p>I have written a recursive algo, based on this very system + divisibility condition, which gives the result for this very problem less than in one minute:</p>


```python
def recursive_perm(n, ks, used):
    if(len(used) == n-1):
        if(ks[-1] not in used and ks[-1] != 0):
            #print(used + [ks[-1]])    
            return (True, used + [ks[-1]])
    
        return (False, None)
    
    for i in range(max(0, (1-ks[-1]) //2), (n-ks[-1])//2 + 1):  # this range is caused by the system conditions on k's
        current_a = ks[-1] + 2 * i
        if(current_a not in used and current_a != 0):
            ans = recursive_perm(n, ks + [i], used + [current_a])
            if(ans[0]):
                return ans
    return (False, None)
```


```python
def get_permutation(n):
    if(n * (n+1) // 2 % 3 != 0):
        print("TINP")
        return None
    for i in range(1, n//2+1):
        ans = recursive_perm(n, [i], [2*i])  # starts with an even number due to the system
        if(ans[0]):
            return ans[1]
```


```python
def assert_sum(perm):
    return sum((-2)**i * perm[i] for i in range(len(perm))) == 0
```


```python
for i in range(3, 41):
    print(i, end=" ")
    permi = get_permutation(i)
    if(permi and assert_sum(permi)):
        print(permi)
```

    3 [2, 3, 1]
    4 TINP
    5 [2, 3, 5, 4, 1]
    6 [2, 3, 5, 6, 4, 1]
    7 TINP
    8 [2, 1, 4, 6, 8, 5, 7, 3]
    9 [2, 1, 4, 6, 8, 5, 7, 9, 3]
    10 TINP
    11 [2, 1, 4, 6, 8, 5, 7, 9, 11, 10, 3]
    12 [2, 1, 4, 6, 8, 3, 10, 7, 11, 9, 12, 5]
    13 TINP
    14 [2, 1, 4, 6, 8, 3, 10, 7, 9, 12, 14, 11, 13, 5]
    15 [2, 1, 4, 6, 8, 3, 10, 7, 9, 12, 14, 11, 13, 15, 5]
    16 TINP
    17 [2, 1, 4, 6, 8, 3, 10, 5, 12, 16, 13, 14, 11, 17, 9, 15, 7]
    18 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 18, 9, 13, 16, 15, 11, 17, 7]
    19 TINP
    20 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 9, 11, 15, 19, 13, 17, 7]
    21 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 9, 11, 15, 19, 13, 17, 21, 7]
    22 TINP
    23 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 13, 11, 15, 19, 21, 17, 23, 9]
    24 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 13, 11, 15, 19, 17, 23, 21, 24, 9]
    25 TINP
    26 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 13, 17, 21, 25, 19, 15, 23, 9]
    27 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 13, 17, 21, 25, 19, 15, 23, 27, 9]
    28 TINP
    29 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 15, 21, 25, 19, 27, 23, 28, 17, 29, 13]
    30 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 15, 17, 23, 27, 21, 28, 25, 29, 19, 30, 13]
    31 TINP
    32 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 13, 28, 19, 30, 23, 27, 25, 29, 21, 31, 17, 32, 15]
    33 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 13, 28, 17, 21, 25, 30, 29, 27, 31, 23, 32, 19, 33, 15]
    34 TINP
    35 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 13, 28, 17, 19, 30, 21, 25, 32, 29, 31, 33, 27, 34, 23, 35, 15]
    36 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 13, 28, 15, 30, 32, 23, 25, 27, 31, 29, 33, 34, 21, 35, 19, 36, 17]
    37 TINP
    38 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 13, 28, 15, 30, 32, 19, 21, 34, 25, 36, 29, 33, 31, 35, 27, 37, 23, 38, 17]
    39 [2, 1, 4, 6, 8, 3, 10, 5, 12, 14, 16, 18, 20, 7, 22, 11, 24, 26, 9, 13, 28, 15, 30, 32, 19, 21, 34, 23, 27, 31, 36, 35, 33, 37, 29, 38, 25, 39, 17]
    40 TINP

