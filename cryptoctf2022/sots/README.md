---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.14.1
  kernelspec:
    display_name: SageMath 9.6
    language: sage
    name: sagemath
---

<h>Task:</h>
<br>
<code>||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|  Hey math experts, in this challenge we will deal with the numbers   |
|  those are the sum of two perfect square, now try hard to find them! |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Generating the `n', please wait...
| Options:
|       [G]et the n
|       [S]olve the challenge!
|       [Q]uit</code>


<p>This problem is related to the well-known mathematical problem of representing a number as the sum of two perfect squares.  Thanks to Gauss, we can solve it by calculating the Gaussian representation of each prime number in the factorization of n as the product of two Gaussian primes (complex integers), and then multiplying their components according to the following formula:</p>
<code>if m = x**2 + y**2 (known representation), than m * (a**2 + b**2) = (a * x + b * y)**2 + (b * x - a * y)**2</code>

```sage
#n = int(input())
n = 3240139923419554942777080012629133756613088443909765152258260143097079289
# it was my number, but it will work for any number given by this task

r = ecm.factor(n) # it was obvious that this number is smooth since the task is marked as easy
r = list(r)
print(r)
```

```sage
G = ZZ[I]
factored = []
for i in r:
    tmp = list(x[0] for x in G(i).factor()) # G(i) factorization is a Gaussian Factorization of a number
    tmp[1] *= I
    factored += [[abs(x) for x in tmp[0]]]
    
ans = factored[0] # taking the first representation as default
for i in factored[1:]:
    a = ans[0] * i[0] + ans[1] * i[1] # applying the above formula
    b = ans[1] * i[0] - ans[0] * i[1]
    ans = [a, b]
print(ans)
```

```sage
assert ans[0]**2 + ans[1]**2 == n
```
