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
p = 7389313481223384214994762619823300589978423075857540712007981373887018860174846208000957230283669342186460652521580595183523706412588695116906905718440770776239313669678685198683933547601793742596023475603667
e = 31337
f = 7236042467316654159796543399639966340258093274047941788600980451877044636122969830708918356119442228154447395855689559447196348683125675305629837437591088260218138895919514078948650757100432223219969122629790
g = 1878626136321051642174045874618248475160620873585704351202865003185878331837410979441756843820270907300810543618813757245154196050399357659526631164136221434463496532263979506870318259276669412698827040743576

x = bytes_to_long(flag.encode('utf-8'))
assert x < p
c = (110 * pow(e, x, p) + 313 * pow(f, x, p) + 114 * pow(g, x, p)) % p
print(f'c = {c}')
```
<!-- #endregion -->

```sage
p = 7389313481223384214994762619823300589978423075857540712007981373887018860174846208000957230283669342186460652521580595183523706412588695116906905718440770776239313669678685198683933547601793742596023475603667
e = 31337
f = 7236042467316654159796543399639966340258093274047941788600980451877044636122969830708918356119442228154447395855689559447196348683125675305629837437591088260218138895919514078948650757100432223219969122629790
g = 1878626136321051642174045874618248475160620873585704351202865003185878331837410979441756843820270907300810543618813757245154196050399357659526631164136221434463496532263979506870318259276669412698827040743576

c = 871346503375040565701864845493751233877009611275883500035764036792906970084258238763963152627486758242101207127598485219754255161617890137664012548226251138485059295263306930653899766537171223837761341914356
```

```sage
print(factor(p-1))
```

<p>As we can see p-1 is a smooth number, hence DLP in this field should be trivial for sage</p>

```sage
G = GF(p)
d1 = discrete_log(G(f), G(e))
d2 = discrete_log(G(g), G(e))
print(d1)
print(d2)
```

<p>Now we can notice that: d1 == p - 2, d2 == p - 3.</p>
<p>Hence f = e**(p-2) = e**(p - 1 - 1) = e**(-1) (mod p)</p>
<p>g = e**(-2) (mod p)</p>
<p>Thus, we can construct a polynomial in terms of e**x</p>

```sage
assert d1 == p - 2
assert d2 == p - 3

var('t')
P = PolynomialRing(GF(p), t)
r = P(110 * t**3 - int(c) * t**2 + 313 * t + 114)
x = r.roots()[0][0]
print(x)
```

<code>e**x = 6621736714803975486469770941631918297557515256645141403866696899656801529069492623812629032566382224631133756513615225604518504150834965984951182186972792703483282014259169249309903503054330793332575590535531</code>

```sage
m = discrete_log(G(x), G(e))
print(int(m).to_bytes(38, 'big'))
```