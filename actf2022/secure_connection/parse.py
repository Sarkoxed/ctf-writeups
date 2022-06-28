s = open("../src/master.txt", "rt").read().split('\n')
from base64 import b64decode

def parse_cond(cond):
    x = int(cond, 16)
    y = (x & 0x3f)
    ans = ''
    d = {1:"hello, ", 2: "sc_req, ", 3: "sc_rsp, ", 4: "m_confirm, ", 5: "s_confirm, ", 6: "m_random, ", 7: "s_random, ", 8: "data, "}
    ans += d[y]

    if(x >> 7 & 0b1):
        ans += "enc, "
    else:
        ans += "no_enc, "

    if(x >> 6 & 0b1):
        ans += "more_data, "
    
#    if(y[2] == '1'):
#        ans += "what, "
#    if(y[3] == '1'):
#        ans += "whaat, "
    
    return ans

def parse_str(mes, le = 0):
    ans = parse_cond(mes[0])
    mes = mes[2:]

    data = "".join(mes[:le])
    if("no_enc" in ans and "confirm" not in ans and "random" not in ans):
        data = bytes.fromhex(data)

    if "hello" not in ans and "no_enc" in ans:
        data = b64decode(data) 
    crc = "".join(mes[le:])
    return ans + f" len: {le}, data: {data}, crc: {crc}"

it = 0
while(it < len(s)):
    li = s[it].split()
    out = ''
    if(li[0] == '>'):
        out += "from, "
    elif(li[0] == '<'):
        out += "to,   "

    li = li[1:] 
    le = int(li[1], 16)
    it += 1
    while(it < len(s) and '>' not in s[it] and '<' not in s[it]):
        li += s[it].split()
        it += 1

    out += parse_str(li, le)
    print(out, '\n')
