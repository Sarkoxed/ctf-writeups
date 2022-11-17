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

<!-- #region -->
<h>Task:</h>
```python
p = k**6 + 7*k**4 - 40*k**3 + 12*k**2 - 114*k + 31377
q = k**5 - 8*k**4 + 19*k**3 - 313*k**2 - 14*k + 14011
n = 44538727182858207226040251762322467288176239968967952269350336889655421753182750730773886813281253762528207970314694060562016861614492626112150259048393048617529867598499261392152098087985858905944606287003243
```
<!-- #endregion -->

```sage
n = 44538727182858207226040251762322467288176239968967952269350336889655421753182750730773886813281253762528207970314694060562016861614492626112150259048393048617529867598499261392152098087985858905944606287003243
enc = 37578889436345667053409195986387874079577521081198523844555524501835825138236698001996990844798291201187483119265306641889824719989940722147655181198458261772053545832559971159703922610578530282146835945192532
```

```sage
var('k')
p = k**6 + 7*k**4 - 40*k**3 + 12*k**2 - 114*k + 31377
q = k**5 - 8*k**4 + 19*k**3 - 313*k**2 - 14*k + 14011
print(expand(p * q))
```

<p>Now we can use the well-known fact that if a polynomial with integer coefficients has an integer root, then it must divide the free coefficient of this very polynomial</p>

```sage
free = n - 439623147
# I have used factordb to factor free
factors_free = [2, 2, 2, 2, 2, 2, 2, 23, 149, 96587, 284489 ,308249, 182920456883, 290346833867442323, 225708816469027874604301730604018953131429251454653530933080485440552052705861610529060326434856162088025503274779451825531308257294418918769464570979364684057]

from itertools import combinations # naive creation of all the divisors
divisors = []
for i in range(len(factors_free)):
    divisors += list(prod(x) for x in combinations(factors_free, i))

for i in divisors:
    if((p * q - n)(k=i) == 0):
        ans = i
        break
        
p = int(p(k=ans))
q = int(q(k=ans))
assert p*q == n

d = pow(31337, -1, (p-1)*(q-1))

print(int(pow(enc, d, n)).to_bytes(50, "big"))
```
