from sage.all import Matrix, vector, Zmod, var, ZZ
import random
class Random:
    def __init__(self, modulus):
        self.r = random.SystemRandom()
        self.modulus = modulus
    def next(self):
        return self.r.randrange(1, self.modulus)
class CentralMapping:
    def __init__(self, o, v, modulus):
        while True:
            self.rng = Random(modulus)
            self.varrng = Random(modulus)
            self.modulus = modulus
            self.o = o
            self.v = v
            self.a = self.generate_a_b(self.o, self.v, self.o)
            self.b = self.generate_a_b(self.v, self.v, self.o)
            self.c = self.generate_c_d(self.o, self.o)
            self.d = self.generate_c_d(self.v, self.o)
            self.e = self.generate_e(self.o)
            if len(list(set(self.e))) > o // 2:
                break

    def generate_a_b(self, i, j, k):
        return [self.generate_c_d(j, k) for _ in range(i)]

    def generate_c_d(self, j, k):
        return [self.generate_e(k) for _ in range(j)]

    def generate_e(self, k):
        return [self.rng.next() for _ in range(k)]

    def raw_eval(self, vars):
        t = []
        o = vars[self.v :]
        v = vars[: self.v]
        for k in range(self.o):
            s = 0
            for i in range(self.o):
                for j in range(self.v):
                    s += self.a[i][j][k] * v[j] * o[i]
                s += self.c[i][k] * o[i]
            s += self.e[k]
            for i in range(self.v):
                for j in range(self.v):
                    s += self.b[i][j][k] * v[i] * v[j]
                s += self.d[i][k] * v[i]
            t.append(s)
        return t

    def invert(self, t):
        v = [self.varrng.next() for _ in range(self.v)]
        o = [var(f"o_{i}") for i in range(self.o)]
        equations = self.raw_eval(v + o)
        coeffs = []
        target = []
        for i in range(self.o):
            eq = equations[i]
            subdict = {o[i]: 0 for i in range(self.o)}
            constant = eq.subs(subdict)
            coeffs.append(
                [int(eq.coefficient(o[i])) % self.modulus for i in range(self.o)]
            )
            target.append(int(int(t[i]) - constant) % self.modulus)
        M = Matrix(Zmod(self.modulus), coeffs)
        A = vector(Zmod(self.modulus), target)
        o = M.solve_right(A)
        o = [int(x) for x in o]
        return v + o

    def eval(self, vars):
        return [x % self.modulus for x in self.raw_eval(vars)]

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(o={self.o}, v={self.v}, modulus={self.modulus})"
        )


class AffineMap:
    def __init__(self, n, modulus):
        self.modulus = modulus
        self.varrng = Random(modulus)
        self.F = Zmod(modulus)
        while True:
            A = Matrix(self.F, self.generate_A(n, n))
            if A.is_invertible():
                break
        self.A = A
        self.Ainv = A.inverse()  # precompute the inverse

    def generate_A(self, m, n):
        return [self.generate_A_row(m) for _ in range(n)]

    def generate_A_row(self, n):
        return [self.varrng.next() for _ in range(n)]

    def raw_eval(self, x):
        A_real = list(self.A)
        data = []
        for i in range(len(A_real)):
            data.append(sum([int(A_real[i][j]) * x[j] for j in range(len(A_real[i]))]))
        return data

    def eval(self, x):
        x = vector(self.F, x)
        return (self.A * x).list()

    def invert(self, y):
        y = vector(self.F, y)
        return (self.Ainv * y).list()

    def __repr__(self):
        return f"{self.__class__.__name__}(n={self.A.nrows()}, modulus={self.modulus})"


class Salad:
    def __init__(self, o, v, modulus):
        self.modulus = modulus
        self.o = o
        self.v = v
        self.AM1 = AffineMap(o + v, modulus)
        self.CM = CentralMapping(o, v, modulus)
        self.AM2 = AffineMap(o, modulus)

    def eval(self, vars):
        vars = self.AM1.eval(vars)
        vars = self.CM.eval(vars)
        vars = self.AM2.eval(vars)
        return vars

    def raw_eval(self, vars):
        vars = self.AM1.raw_eval(vars)
        vars = self.CM.raw_eval(vars)
        vars = self.AM2.raw_eval(vars)
        return vars

    def invert(self, vars):
        vars = self.AM2.invert(vars)
        vars = self.CM.invert(vars)
        vars = self.AM1.invert(vars)
        return vars

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(o={self.o}, v={self.v}, modulus={self.modulus})"
        )
