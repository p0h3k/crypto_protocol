import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Инициализация параметров
p = int(input("Enter simple p = ")) #Example p = 23
g = int(input("Enter g = ")) #Example = 5

# Генерация ключей для Алисы и Боба
keypair_Alice = RSA.generate(2048)
keypair_Bob = RSA.generate(2048)

# Алиса выбирает случайное число и отправляет сообщение Бобу
x = random.randint(2, p - 1)
mA = pow(g, x, p)

print("Alice message = ",mA)
# Боб выбирает случайное число, вычисляет свое сообщение и секретный ключ
y = random.randint(2, p - 1)
mB = pow(g, y, p)
K_Bob = pow(mA, y, p)

print("Bob message = ", mB)
# Боб создает подпись
h = SHA256.new(str(mB).encode() + str(mA).encode())
signature_Bob = pkcs1_15.new(keypair_Bob).sign(h)

# Алиса вычисляет секретный ключ и проверяет подпись Боба
K_Alice = pow(mB, x, p)

try:
    pkcs1_15.new(keypair_Bob.publickey()).verify(h, signature_Bob)
    print("The signature is valid.")
except (ValueError, TypeError):
    print("The signature is not valid.")
    
# Подпись Алисы
h = SHA256.new(str(mA).encode() + str(mB).encode())
signature_Alice = pkcs1_15.new(keypair_Alice).sign(h)

# Боб проверяет подпись Алисы
try:
    pkcs1_15.new(keypair_Alice.publickey()).verify(h, signature_Alice)
    print("The signature is valid.")
except (ValueError, TypeError):
    print("The signature is not valid.")
  
# Проверка секретных ключей
print("Shared secret keys match:", K_Alice == K_Bob)
print("Alice secret key = ", K_Alice)
print("Bob secret key = ", K_Bob)
