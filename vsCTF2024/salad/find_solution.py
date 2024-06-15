from sage.all import PolynomialRing, GF, ZZ, Matrix, vector, next_prime


def find_single_matrix(K, nv, A, a):
    tmp_m = []
    for k in range(K):
        Ak = A[k]
        tmp_row = []
        for j in range(nv):
            s1 = 0
            for i in range(nv):
                sc = 2 if i == j else 1
                s1 += Ak[i][j] * a[i] * sc
            tmp_row.append(s1)
        tmp_m.append(tmp_row)
    return tmp_m


def find_ai(K, nv, A, as_, F):
    tmp_m = []
    for a in as_:
        tmp_m += find_single_matrix(K, nv, A, a)

    M = Matrix(F, tmp_m)
    ai = M.right_kernel().random_element()
    as_.append(ai)


def find_transformation(polys, vars_, n):
    F = polys[0].base_ring()
    K = len(polys)
    nv = len(vars_)

    A = [
        [[polys[k][vars_[i] * vars_[j]] for i in range(nv)] for j in range(nv)]
        for k in range(K)
    ]
    as_ = []
    for i in range(n):  # !!!!
        if i == 0:
            as_.append([F.random_element() for _ in range(nv)])
        else:
            find_ai(K, nv, A, as_, F)

    for _ in range(20):  # try to find bijection
        as_tmp = as_.copy()
        for _ in range(n, nv):
            as_tmp.append([F.random_element() for _ in range(nv)])
        if Matrix(as_tmp).det() != 0:
            return Matrix(as_tmp).T

    return None


def solve_linear_equations(linear_polys, vars_):
    F = linear_polys[0].base_ring()
    v = len(vars_)
    res_matr = Matrix(F, v)
    res_vector = vector(F, v)
    for i, poly in enumerate(linear_polys):
        for j, var in enumerate(vars_):
            res_matr[i, j] = poly.coefficient(var)
        res_vector[i] = -poly.constant_coefficient()
    print(res_matr.det())

    try:
        sol = res_matr.solve_right(res_vector)
        return sol
    except Exception as e:
        print(e)
        print("no linear")


def find_solution_to_the_system(polys, A, vars_, n, F):
    nv = len(vars_)
    K = len(polys)

    subs = {vars_[i]: sum(A[i][j] * vars_[j] for j in range(nv)) for i in range(nv)}
    polys_transformed = []
    for poly in polys:
        polys_transformed.append(poly.subs(subs))

    linears = []
    for k in range(K):
        for y in vars_[:n]:
            tmp_lin = polys_transformed[k].coefficient(y)
            linears.append(tmp_lin)

    res = solve_linear_equations(linears, vars_[n:])
    if res is None:
        return None
    # print(f"{res = }")
    if res == 0:
        return None

    squares = []
    subs = {var: val for var, val in zip(vars_[n:], res)}
    for poly in polys_transformed:
        squares.append(poly.subs(subs))

    SQ = Matrix(F, n)
    sq_slv = vector(F, n)
    for k in range(K):
        for i, y in enumerate(vars_[:n]):
            tmp_sq = squares[k].coefficient(y**2)
            SQ[k, i] = tmp_sq
        sq_slv[k] = -squares[k].constant_coefficient()

    try:
        final_vars = SQ.solve_right(sq_slv)
        print(final_vars)
        if all(x.is_square() for x in final_vars):
            tmp_res = [x.sqrt() for x in final_vars] + list(res)
            res = A.change_ring(F) * vector(F, tmp_res)
            return res
        print("not squares")
    except Exception as e:
        print(e)
        print("Not solvable")


def find_solution(polys, vars_, n, F):
    A = find_transformation(polys, vars_, n)
    while A.det() == 0:
        A = find_transformation(polys, vars_, n)
    sol = find_solution_to_the_system(polys, A, vars_, 4, F)
    i = 0
    while sol is None and i < 200:
        print(i)
        A = find_transformation(polys, vars_, 4)
        sol = find_solution_to_the_system(polys, A, vars_, 4, F)
        i += 1
    
    print(sol)
    return sol


if __name__ == "__main__":
    p = next_prime(2**16)
    F = GF(p)
    R2 = F[",".join(f"z_{i}" for i in range(20))]
    ps = [R2.random_element(degree=2) for _ in range(4)]

    vals = [F.random_element() for _ in range(20)]

    evals = [ps[i].subs({z: k for z, k in zip(R2.gens(), vals)}) for i in range(4)]

    ps1 = [poly - ev for poly, ev in zip(ps, evals)]

    sol = find_solution(ps1, R2.gens(), 4, R2)
    if sol is None:
        print("Didn't find")
    evals1 = [ps[i].subs({z: k for z, k in zip(R2.gens(), sol)}) for i in range(4)]
    print(vector(GF(p), evals))
    print(vector(GF(p), evals1))
