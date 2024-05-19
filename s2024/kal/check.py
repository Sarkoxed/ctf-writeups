import solve_z3

ans = [237, 228, 237, 200, 154, 235, 5, 42, 39, 46, 237, 78, 5, 71, 156, 91, 253, 197, 250, 45, 131, 198, 135, 237, 101, 167, 240, 236, 197, 229, 25, 127]

ans = [solve_z3.int8(x) for x in ans]

print(solve_z3.check52(ans))
#for i in range(1, 54):
#    print(i, eval(f"solve_z3.check{i}(ans)"))
