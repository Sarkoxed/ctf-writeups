import os
import subprocess
from solve_z3 import *
from tqdm import tqdm

def py_api(ans, i):
    func = eval(f"check{i}")
    return func(ans)

def c_api(ans, i):
    c_code = ['#include "final_int.c"']
    c_code.append('')
    c_code.append('int main(){')
    c_code.append("char ans[0x32] = {" + str(ans).strip("[]") + "};")
    c_code.append(f"int res = check{i}(ans);")
    c_code.append('printf("%d", res);')
    c_code.append("return 0;")
    c_code.append("}")

    with open("tmp.c", "wt") as f:
        f.write("\n".join(c_code))
    
    pwd = "/home/sarkoxedaf/Working/CTF/2024/sas/rev/clean_thoughts/"
    subprocess.run(["gcc", pwd + "tmp.c", "-o", pwd + "check.out"])
    res = subprocess.run([pwd + "check.out"], capture_output=True).stdout.decode()
    return int(res)


func_out = int(input("check n: "))
for _ in tqdm(range(100)):
    ans = list(os.urandom(0x20))

    c_res = c_api(ans, func_out)
    py_res = py_api([int8(x) for x in ans], func_out)
    if c_res != py_res:
        print(f"C: {c_res}     {c_res == py_res}")
        print(f"Py: {py_res}")
 
        print(ans)
        break
