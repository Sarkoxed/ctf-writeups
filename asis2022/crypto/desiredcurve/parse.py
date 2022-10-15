arr = []
for i in range(int(input())):
    x = input()
    x = int(x[x.index('=') + 1:])
    arr.append(x)
print(arr)
