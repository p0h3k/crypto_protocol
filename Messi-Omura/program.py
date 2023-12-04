import random
from sympy import isprime, mod_inverse
from Crypto.Util import number


def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

def choose_e(phi):
    """Choose an e coprime to phi"""
    while True:
        e = random.randrange(2, phi - 1)
        if gcd(e, phi) == 1:
            return e



bits = int(input("Enter bits lenght for simple p = "))
p = number.getPrime(bits)

phi = p - 1
eA = choose_e(phi)
eB = choose_e(phi)

dA = mod_inverse(eA, phi)
dB = mod_inverse(eB, phi)


m = random.randrange(2, p-1)
print(f"Секретное сообщение: {m}")

#Алиса отправляет зашифрованное сообщение своим ключом
m1 = pow(m, eA, p)

print(f"Сообщение m1: {m1}")

#Боб шифрует сообщение m1 своим ключом 
m2 = pow(m1, eB, p)

print(f"Сообщение m2: {m2}")
#Алиса расшифровывает сообщение m2 вторым ключом 
m3 = pow(m2, dA, p)
print(f"Сообщение m3: {m3}")

#Боб расшифровывает сообщение m3 вторым ключом
m4 = pow(m3, dB, p)


if(m == m4):
    print(f"Боб получил сообщение: {m4}")
