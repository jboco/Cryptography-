from math import sqrt
from math import gcd

import random

def isPrime(n):
    if n < 2:
        return False
    elif n == 2:
        return True
    else:
        for i in range(3, int(sqrt(n))+1, 2 ):
            if n%i == 0:
                return False
    return True 

def generate_rsa_key (p,q):
    if( isPrime(p) == False or isPrime(q) == False):
        raise ValueError("p and q must be prime numbers")

    n= p*q
    phi= (p-1)*(q-1)
    e= random.randrange(2,phi-1)
    while True:
        try: 
            d= pow(e, -1, phi)
            if gcd(e,phi)== 1 and e != d:
                break
        except ValueError:
            print('Generating another value of e after inv mod failed')
        e= random.randrange(2,phi-1)
        
    print ('d = ' , d)
    print ('e = ', e)
    print ('n = ', n)
    return (d, e, n)

def encrypt_text (e, n, txt):
    encrypted_txt= ''
    for i in txt:
        encrypted_txt= encrypted_txt + chr(pow(ord(i),e,n))
    return encrypted_txt

def decrypt_text (n, d, encrypted_txt):
    decrypted_txt= ''
    for i in encrypted_txt:
        decrypted_txt= decrypted_txt+ chr(pow(ord(i),d,n))

    return decrypted_txt


p=79

q=83

d, e, n = generate_rsa_key(p,q)

msg ='Thanks!!'

encrypted_msg = encrypt_text(e, n, msg)
decrypted_msg = decrypt_text(n, d, encrypted_msg)
print('message is: ', msg)

print('encrypted msg is: ', encrypted_msg)
print('decrypted msg is: ', decrypted_msg )

        
    




            
