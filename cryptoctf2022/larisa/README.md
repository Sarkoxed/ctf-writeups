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
<p>Firstly, Note that all that powlat does is simply raisng all the permutations in the list to the power of 65537, hence we can simply reverse this operation by taking the invers of 65537 modulo order of the symmetric group 128</p>

```sage
f = eval(open("enc.txt", "rt").read())
S = SymmetricGroup(128)
c = [S(x) for x in f]
power_d = int(pow(0x10001, -1, S.order()))
m = [x**power_d for x in c]

m = [list(x.tuple()) for x in m]
```

<p>Now we can simply iterate over all possible iR's and iS's to get the correct ones</p>

```sage
k1 = '_' * 30
r = ''
for iR in range(128):
    for iS in range(128):
        ans = ''
        try:
            for k in range(len(k1)):
                ans += chr(m[k][(k * iR + iS) % 128])
            if(ans.isprintable() and '_' in ans):
                print(ans, iR, iS)
        except Exception as e:
            continue
```

```sage
iR, iS = 63, 61
for i in range(len(m)):
    r += chr(m[i][(i * iR + iS) % 128])
print(r)
```
