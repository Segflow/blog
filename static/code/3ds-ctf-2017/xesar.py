from collections import Counter
from itertools import izip, cycle

# encrypted_message_raw.bin is the result of running
# $ base64 -D encrypted_message.txt > encrypted_message_raw.bin
with open("encrypted_message_raw.bin") as f:
    encrypted = f.read()

def shift(data, offset):
    return data[offset:] + data[:offset]

def count_same(a, b):
    count = 0
    for i in range(len(a)):
        if a[i] == b[i]:
            count += 1
    return count

print ('key lengths')
for key_len in range(1, 33): # try multiple key lengths
    freq = count_same(encrypted, shift(encrypted, key_len))
    print ('{0:< 3d} | {1:3d} |'.format(key_len, freq) + '=' * (freq / 4))


key_len = 10
columns = []
for i in range(0, key_len):
    col = []
    for ch in encrypted[i::key_len]:
        col.append(ch)
    columns.append(col)


def most_frequent(text):
    frequency = Counter()
    for x in text:
        frequency[x] += 1
    char, count = frequency.most_common(1)[0]
    return char

key = ""
for col in columns:
    f = most_frequent(col)
    key = key + chr(ord(f) ^ ord(" "))

key = key[:6] + "K" + key[7:] # let's patch the key manually

def decrypt(c_num, k_num):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(c_num, cycle(k_num)))

print (decrypt(encrypted, key))
