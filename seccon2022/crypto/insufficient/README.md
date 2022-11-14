# SECCON 2022
## insufficient(164 pt, 33 solves)
### Task description:
<pre>SUGOI SECRET SHARING SCHEME with insufficient shares</pre>

### Attachments: 

```python
from random import randint
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG


# f(x,y,z) = a1*x + a2*x^2 + a3*x^3
#          + b1*y + b2*y^2 + b3*y^3
#          + c*z + s mod p
def calc_f(coeffs, x, y, z, p):
    ret = 0
    ret += x * coeffs[0] + pow(x, 2, p) * coeffs[1] + pow(x, 3, p)*coeffs[2]
    ret += y * coeffs[3] + pow(y, 2, p) * coeffs[4] + pow(y, 3, p)*coeffs[5]
    ret += z * coeffs[6]
    ret += coeffs[7]

    return ret % p


p = getPrime(512)


# [a1, a2, a3, b1, b2, b3, c, s]
coeffs = [randint(0, 2**128) for _ in range(8)]

key = 0
for coeff in coeffs:
    key <<= 128
    key ^= coeff

cipher_text = bytes_to_long(FLAG) ^ key
print(cipher_text)

shares = []
for _ in range(4):
    x = randint(0, p)
    y = randint(0, p)
    z = randint(0, 2**128)

    w = calc_f(coeffs, x, y, z, p)
    packed_share = ((x,y), w)
    shares.append(packed_share)

print(p)
print(shares)
```


```python
ct = 115139400156559163067983730101733651044517302092738415230761576068368627143021367186957088381449359016008152481518188727055259259438853550911696408473202582626669824350180493062986420292176306828782792330214492239993109523633165689080824380627230327245751549253757852668981573771168683865251547238022125676591
p = 8200291410122039687250292442109878676753589397818032770561720051299309477271228768886216860911120846659270343793701939593802424969673253182414886645533851
params = params = [((6086926015098867242735222866983726204461220951103360009696454681019399690511733951569533187634005519163004817081362909518890288475814570715924211956186561, 180544606207615749673679003486920396349643373592065733048594170223181990080540522443341611038923128944258091068067227964575144365802736335177084131200721), 358596622670209028757821020375422468786000283337112662091012759053764980353656144756495576189654506534688021724133853284750462313294554223173599545023200), ((1386358358863317578119640490115732907593775890728347365516358215967843845703994105707232051642221482563536659365469364255206757315665759154598917141827974, 4056544903690651970564657683645824587566358589111269611317182863269566520886711060942678307985575546879523617067909465838713131842847785502375410189119098), 7987498083862441578197078091675653094495875014017487290616050579537158854070043336559221536943501617079375762641137734054184462590583526782938983347248670), ((656537687734778409273502324331707970697362050871244803755641285452940994603617400730910858122669191686993796208644537023001462145198921682454359699163851, 7168506530157948082373212337047037955782714850395068869680326068416218527056283262697351993204957096383236610668826321537260018440150283660410281255549702), 1047085825033120721880384312942308021912742666478829834943737959325181775143075576517355925753610902886229818331095595005460339857743811544053574078662507), ((5258797924027715460925283932681628978641108698338452367217155856384763787158334845391544834908979711067046042420593321638221507208614929195171831766268954, 4425317882205634741873988391516678208287005927456949928854593454650522868601946818897817646576217811686765487183061848994765729348913592238613989095356071), 866086803634294445156445022661535120113351818468169243952864826652249446764789342099913962106165135623940932785868082548653702309009757035399759882130676)]
```

The main idea behind the solution is the <a href=https://github.com/Sarkoxed/ctf-writeups/blob/master/seccon2022/crypto/insufficient/BarakShaniPhD.pdf>Hidden Number Problems</a>. Especially section 5.1 Solutions. However their Lattice did not work out for me however I was able to come up with a solution, based on their one.

Consider the Lattice, spanned by the raws of the $10$x$10$ matrix:<br>

```math
L =
\begin{bmatrix}
   p & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
   0 & p & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
   0 & 0 & p & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
   0 & 0 & 0 & p & 0 & 0 & 0 & 0 & 0 & 0 \\
   x_1 & x_2 & x_3 & x_4 & t & 0 & 0 & 0 & 0 & 0 \\
   x_1^2 & x_2^2 & x_3^2 & x_4^2 & 0 & t & 0 & 0 & 0 & 0 \\
   x_1^3 & x_2^3 & x_3^3 & x_4^3 & 0 & 0 & t & 0 & 0 & 0 \\
   y_1 & y_2 & y_3 & y_4 & 0 & 0 & 0 & t & 0 & 0 \\
   y_1^2 & y_2^2 & y_3^2 & y_4^2 & 0 & 0 & 0 & 0 & t & 0 \\
   y_1^3 & y_2^3 & y_3^3 & y_4^3 & 0 & 0 & 0 & 0 & 0 & t
\end{bmatrix}
```

And two vectors:

```math
\vec{s} = (-r_1, -r_2, -r_3, -r_4, a_1, a_2, a_3, b_1, b_2, b_3)
```

```math
\vec{h} = (w_1, w_2, w_3, w_4, 0, 0, 0, 0, 0, 0)
```

Note that the vector 

```math
\vec{u} = ({w_1 - c z_1 - s}, {w_2 - c z_2 - s}, {w_3 - c z_3 - s}, {w_4 - c z_4 - s}, a_1 t, a_2 t, a_3 t, b_1 t, b_2 t, b_3 t) = \vec{s} L
```
Hence it is within the Lattice!

Furthermore

```math
\begin{Vmatrix} {\vec{h} - \vec{u}} \end{Vmatrix}^{\!2} = \displaystyle\sum_{i=0}^4(c z_i - s)^2 + a_1^2 t^2 + a_2^2 t^2 + a_3^2 t^2 + b_1^2 t^2 + b_2^2 t^2 + b_3^2 t^2 \le 4 (2^{128} 2^{128} - 2^{128})^2 + 6 * t^2 (2^{128})^2 \approx 2^{514} + 3 * 2^{257} t^2
```

Using Gaussian expected shortest length we can restrict $t$ to make possible the use of Babai closest vertex/plane algorithm to find the Approximate Closest Vector $\vec{u}$ to $\vec{h}$ in $L$ with reduced basis. Also we need this norm to be as small as possible.

So, we should find $t$, such that $$2^{514} + 3 * 2^{257} t^2 \lt \frac{ (\Gamma (1 + \frac{n}{2})det(L))^{\frac{2}{n}} }{\pi} = \frac{ (120 p^4 t^6)^{\frac{1}{5}} }{\pi}$$

We can find the turning point via binary search!


```python
x = var('x')
f = 2**514 + 3 * 2**129 * x - (120 * p**4 * x**6)**(1/5)/pi
a, b = 0, 2**512
gt = []
while True:
    mid = (a + b)//2
    g = f(x=mid).n()
    if g > 0:
        a = mid
    elif g < 0:
        b = mid
    if b <= a + 1:
        break
    if(f(x=a).n() > 0):
        gt.append(a)
print(f(x=a).n(), a)
print(f(x=b).n(), b)
```

    4.16798398060073e139 251028658364543899663335424
    -1.07176730929733e140 251028658364543899663335425


Now we can assume that for $t \ge 251028658364543899663335425$ this inequality holds.


```python
def nearest(x):
    if abs(floor(x) - x) < 0.5:
        return floor(x)
    return ceil(x)


def gen_matrix(p, params, t = 1):
    m = len(params)
    d = 6
    M = Matrix(ZZ, m + d, m + d)
    M.set_block(0, 0, identity_matrix(m) * p)
    M.set_block(m, m, identity_matrix(d) * t)
    h = []
    for i in range(m):
        x, y = params[i][0]
        h.append(params[i][1])
        inte = matrix([x, x**2, x**3  , y, y**2 , y**3 ]).T
        M.set_block(m, i, inte)
    h = h + [0] * d
    return M, vector(h)

def Babai_closest_vertex(base, vec):
    m = Matrix(base)
    sol = m.solve_left(vec)
    sol = vector([nearest(x) for x in sol])
    ans = zero_vector(len(base))
    for i in range(len(base)):
        ans += vector(base[i]) * sol[i]
    return ans
```


```python
t = 251028658364543899663335425 
M, h = gen_matrix(p, params, t)
m = M.LLL()
m = [x for x in m]
u = Babai_closest_vertex(m, h)
assert (u - h).norm() < (120 * p**4 * t**6)**(1/10)/sqrt(pi)
s = M.solve_left(u)
print(s)
```

    (-3788473450022742507797205428359131458883090620125715480516636644666253357085237853861265276777234820444576367858685461658224947154247995799840283189799842364604042814472860901973742122656190763446357734856697811441170615800167767277155233860204167097801176391080592098338404898415844429826771077805730094404287472481610447752223934820033752325791, -272674018717101800614776524069415159863363984203554741202583344835752007363583784909574517690355428611618193730772879760872221020484222542365276986651635669105336395834558798543523285709325686668416435036667176002796050464342116311786243284826597650685414093119279797667582363298514044038498692773163491595434623936189155239263043808990541414012, -1262483761334323490652006913517659565556009174110757765688909130366092015651092092566993097729417172237584887189965982930589552615824770118199191192013006019585344677112448536349299377978905803636814134481898603348141818511774231441943553642574816457204241953306163478653939202642039603359304891924866526571469707813120784710703852321742388926608, -2738914733803296418428205286039060243899551569183374085482599581355475941348887258845483483548725033674983908663309882321778222544582503209093588868738095161957191280766671823962708597193786381474575240223688848187045778621629326750810845312043862968921618140490645568531059283837280231663754938004458055182277282757035551708156840416504316755726, 319946859331022505606006682830489529550, 152251339815807627609342474617581741055, 137751761597342098624908697775689190697, 337281036453915579622200616302875159873, 150513307904359194457545638585602396040, 27998232432567560780529247469815955088)


We have successfully recovered $a_1, a_2, a_3, b_1, b_2, b_3$

Now we can use a few triks to find $s$ and $c$

First of all, note that since $c z_i + s < 2^{256} < p$ we can solve the rest of the equations over the Integers.


```python
a1, a2, a3, b1, b2, b3 = s[-6:]
rs = []
for _ in range(4):
    x, y = params[_][0]
    w = params[_][1]
    r0 = (w - (a1*x + a2 * x**2 + a3 * x**3 + b1 * y + b2 * y**2 + b3 * y**3)) % p
    rs.append(r0)
r1, r2, r3, r4 = rs
```

$$c z_1 + s = r_1 \\ c z_2 + s = r_2 \\ c z_3 + s = r_3 \\ c z_1 + s = r_4$$

Sice the values are pretty random, we can assume that the   $gcd(r_2 - r_1, r_3 - r_2, r_4 - r_3) = c$


```python
c = gcd([r2 - r1, r3 - r2, r4 - r3])
print(int(c).bit_length())
```

    128


The following part to recover $s$ is pretty obvious.


```python
z1 = floor((r1 - 2**128) / c)  # using boundaries for s
z2 = ceil((r1 - 2**127) / c)

for z in range(z1, z2+1):
    s = r1 - c * z
    if s > 0 and int(s).bit_length() == 128:
        break
print(s)
```

    86246982746739283466217140132251503442



```python
coeffs = [a1, a2, a3, b1, b2, b3, c, s]
coeffs = [int(x) for x in coeffs]

key = int(0)
for coeff in coeffs:
    key <<= 128
    key ^^= coeff

from Crypto.Util.number import long_to_bytes
flag = ct ^^ key
print(long_to_bytes(flag))
```

    b'SECCON{Unfortunately_I_could_not_come_up_with_a_more_difficult_problem_than_last_year_sorry...-6fc18307d3ed2e7673a249abc2e0e22c}'


Also there was another way, that requires less theory knowledge: just to search for that t:


```python
a, b = 0, p
while True:
    t = (a + b) // 2
    M, h = gen_matrix(p, params, t)
    m = M.LLL()
    m = [x for x in m]
    u = Babai_closest_vertex(m, h)
    s = M.solve_left(u)
    
    z = int(abs(s[-1])).bit_length()
    if z >= 127 and z <= 128 and all(x > 0 and int(x).bit_length() <= 128 for x in s[-6:]):
        print(t)
        break
    elif z > 128:
        a = t + 1
    else:
        b = t - 1
    if b <= a + 1:
        break

a1, a2, a3, b1, b2, b3 = s[-6:]
rs = []
for _ in range(4):
    x, y = params[_][0]
    w = params[_][1]
    r0 = (w - (a1*x + a2 * x**2 + a3 * x**3 + b1 * y + b2 * y**2 + b3 * y**3)) % p
    rs.append(r0)
r1, r2, r3, r4 = rs
c = gcd([r2 - r1, r3 - r2, r4 - r3])
z1 = floor((r1 - 2**128) / c)  # using boundaries for s
z2 = ceil((r1 - 2**127) / c)

for z in range(z1, z2+1):
    s = r1 - c * z
    if s > 0 and int(s).bit_length() == 128:
        break

coeffs = [a1, a2, a3, b1, b2, b3, c, s]
coeffs = [int(x) for x in coeffs]

key = int(0)
for coeff in coeffs:
    key <<= 128
    key ^^= coeff

from Crypto.Util.number import long_to_bytes
flag = ct ^^ key
print(long_to_bytes(flag))
```

    b'SECCON{Unfortunately_I_could_not_come_up_with_a_more_difficult_problem_than_last_year_sorry...-6fc18307d3ed2e7673a249abc2e0e22c}'

