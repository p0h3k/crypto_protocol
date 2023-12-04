import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number


# Инициализация параметров
#p = int(input("Enter simple p = ")) #Example p = 23
bits = int(input("Enter bits lenght for simple p = "))
p = number.getPrime(bits)
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

	
# Боб шифрует подпись с помощью общего секрета. Сначала вычисляется SHA256 от общего секрета, потом шифруется с помощью  AES. И отправляет Алисе зашифрованную подпись
key_Bob = SHA256.new(str(K_Bob).encode()).digest()
cipher_Bob = AES.new(key_Bob, AES.MODE_CBC)
encrypt_signature_Bob = cipher_Bob.encrypt(pad(signature_Bob, AES.block_size))


# Алиса вычисляет секретный ключ и проверяет подпись Боба
K_Alice = pow(mB, x, p)
key_Alice = SHA256.new(str(K_Alice).encode()).digest()
cipher_Alice = AES.new(key_Alice, AES.MODE_CBC)


# Алиса расшифровывает подпись Боба 
cipher_decrypt_Alice = AES.new(key_Alice, AES.MODE_CBC, iv=cipher_Bob.iv)
decrypted_message = unpad(cipher_decrypt_Alice.decrypt(encrypt_signature_Bob), AES.block_size)


if (decrypted_message == signature_Bob):
    print("Alice success decrypt Bob signature")
    try:
        pkcs1_15.new(keypair_Bob.publickey()).verify(h, signature_Bob)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")



    
# Подпись Алисы
h = SHA256.new(str(mA).encode() + str(mB).encode())
signature_Alice = pkcs1_15.new(keypair_Alice).sign(h)
encrypt_signature_Alice = cipher_Alice.encrypt(pad(signature_Alice, AES.block_size))

# Боб расшифровывает подпись Алисы 
cipher_decrypt_Bob = AES.new(key_Bob, AES.MODE_CBC, iv=cipher_Alice.iv)
decrypted_message = unpad(cipher_decrypt_Bob.decrypt(encrypt_signature_Alice), AES.block_size)

# Боб проверяет подпись Алисы
if (decrypted_message == signature_Alice):
    print("Bob success decrypt Alice signature")
    try:
        pkcs1_15.new(keypair_Alice.publickey()).verify(h, signature_Alice)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


  
# Проверка секретных ключей
print("Shared secret keys match:", K_Alice == K_Bob)
print("Alice secret key = ", K_Alice)
print("Bob secret key = ", K_Bob)
