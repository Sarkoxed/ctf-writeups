---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.14.1
  kernelspec:
    display_name: SageMath 9.7
    language: sage
    name: sagemath
---

# Mindseat

## Description
<pre>Cryptography Mindset: Be Unpredictable, build robust and stable applications where you'll handle every situation that user can face or predict.

Please re-download the task file!
</pre>
<b>Attachments in repo</b>

## Solution
First of all, what the fix was about? Well, in the first version of this task _p was random prime of order 2^12. Now it's 1 and me very happy with this fact.<br>
Ok, we have a bunch of public keys:<br>
    <code>s_i^m_i * r_i ^ (2 ^ k) = c_i (mod n_i)</code>
where <code>i = 4, PK_i = (s_i, n_i)</code><br>
Further I'm not going to keep <code>_i</code> index, but keep it in mind.<br>
From the source code we can see that each <code>p_i, q_i</code> are:<br>
<code>p = 1 + 2^k * R1, where R1 - (nbit-k) bit random integer</code><br>
<code>q = 1 + 2^k * R2, where R1 - (nbit-k) bit random integer</code><br>
Hence, ```n = 1 + 2^k * (R1 + R2) + 2^(2 * k) * R1 * R2```<br>
and ```n-1``` is divisible by ```2^k```

```sage
PUBKEYS = [(10342840547250370454282840290754052390564265157174829726645242904324433774727630591803186632486959590968595230902808369991240437077297674551123187830095873, 5179654005441544601140101875149402241567866059199512232495766031194848985776186595289740052214499657697650832860279375151687044465018028876445070588827777), (6015512135462554031390611730578383462516861987731833360559070749140159284050335604168414434218196369921956160353365713819898567416920672209509202941444097, 2116441415129068001049624780654272734931672052541246678702416144768611225693039503554945326959705314527114860312641379671935648337975482830939466425225421), (6396980904648302374999086102690071222661654639262566535518341836426544747072554109709902085144158785649143907600058913175220229111171441332366557866622977, 1760317994074087854211747561546045780795134924237097786412713825282874589650448491771874326890983429137451463523250670379970999252639812107914977960011738), (9158217300815233129401608406766983222991414185115152402477702381950519098200234724856258589693986849049556254969769863821366592458050807400542885348638721, 6564146847894132872802575925374338252984765675686108816080170162797938388434600448954826704720292576935713424103133182090390089661059813982670332877677256)]
ENCS = [4595268033054096192076432659360373235610019564489694608733743330870893803828258295069937060360520598446948290913045781945314108935153236291467160667601985, 3390637292181370684803039833768819598968576813582112632809296088618666221278429695211004046274005776653775480723833818255766663573061866194380012311184611, 5197599582013327040903216369733466147938613487439777125659892779696104407398257678982801768761973934713675657188014051286238194316997970299887749668838196, 5093835186720390391696398671365109925058893544530286148616117890366909889206952477053316867658405460457795493886317792695055944930027477761411273933822112]
```

```sage
k = 256
for n, s in PUBKEYS:
    ki = 0
    tmp = n - 1
    while tmp % 2**(ki+1) == 0:
        ki += 1
    if ki < k:
        k = ki
print(k)
```

```sage
print(PUBKEYS[0][0].bit_length())
```

Next, we know that ```k is 134 bits``` and ```n is 512 bits``` hence ```nbit is probably 256``` and ```R1, R2 are 256 - 134 = 122 bis```<br>
From there we know that ```R1 + R2 ~ 123 bits < 2**k```, and we can recover R1 + R2.<br>
Thats all, we have recovered R1 + R2, and we know ```(R1 * R2 which is n-1 - 2^k * sum) // 2^(2*k)```

```sage
from Crypto.Util.number import long_to_bytes

ans_f = b''
for p, c in zip(PUBKEYS, ENCS):
    n, s = p
    sum_r1r2 = ((n - 1) // 2**k) % 2**k
    prod_r1r2 = (n - 1 - 2**k * sum_r1r2 ) // 2**(k * 2)
    
    var('x')
    t = x**2 - sum_r1r2 * x + prod_r1r2
    r1, r2 = t.roots()
    r1 = r1[0]
    r2 = r2[0]
    
    p = 1 + 2**134 * r1
    q = 1 + 2**134 * r2
    g = GF(p)                    # after finding p and q we can move to the subgroup of order p - 1 
                                 # and easily solve dlp there

    cc = g(c)**r1                # getting rid of nasty r_i^(2^k), since 2^k * r1 is the order of this group
    
    t1 = discrete_log(g(cc), g(s))
    
    rr = pow(int(r1), -1, p)    
    tt = g(t1) * g(rr)           # getting rid of r_i which we used before to get rid of r_i
    
    ans = int(tt)
    ans_f += long_to_bytes(ans)
print(ans_f)
```
