a = list('88¦-n+¦++\x03+¦-n+-¦\x03-¦')
print(len(a))

for i in range(20):
    print(chr(((ord(a[i])-52)^251)+1336),end=' ')
print()

for j in range(256):
    for minus in range(256):
        b = ''
        for i in range(20):
            try:
                b+=chr((ord(a[i])-minus)^j)
            except ValueError:
                break
        if 'CC{' in b:
            print(b)
