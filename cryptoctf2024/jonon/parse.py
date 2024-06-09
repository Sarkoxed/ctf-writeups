with open('out3', 'r' ) as f:
    data = f.read()

def parse_line(line):
    line = line.replace('[', '').replace(']', '')
    line = line.split(' ')
    line = list(filter(lambda a: a != '', line))
    return list(map(int, line))

def parse_all_matricies():
    matricies = []
    m = []
    for line in data.split('\n'):
        if line == '':
            matricies.append(m)
            m = []
            continue
        m.append(parse_line(line))
    return matricies

matricies = parse_all_matricies()[:-1]
C = matricies[-1]
pkey = matricies[:-1]
