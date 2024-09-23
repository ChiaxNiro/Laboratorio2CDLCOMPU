import random
from sympy import mod_inverse

def miller_rabin_primo(bits=512, k=5):
    def miller_rabin(n, k):
        if n == 2 or n == 3:
            return True
        if n % 2 == 0 or n < 2:
            return False

        s = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, n - 2)

            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    while True:
        n = random.getrandbits(bits)
        
        if miller_rabin(n, k):
            return n

def generar_claves(bits=512):
    p = miller_rabin_primo(bits=512, k=5)
    q = miller_rabin_primo(bits=512, k=5)
    n = p * q
    phi_n = (p - 1) * (q - 1)  

    e = 65537  

    d = mod_inverse(e, phi_n)  
    return (e, n), (d, n), (p, q)

# Se generan las claves
public_key, private_key, primos = generar_claves()
print("Clave Pública:", public_key)
print("Clave Privada:", private_key)

def cifrar_mensaje(message, public_key):
    e, n = public_key
    message_as_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    encrypted_message = pow(message_as_int, e, n)
    return encrypted_message

# Acá insertamos el mensaje a cifrar
mensaje = "Buenos dias este es un mensaje de prueba prueba"
mensaje_cifrado = cifrar_mensaje(mensaje, public_key)
print("Mensaje Cifrado:", mensaje_cifrado)

def decifrar_mensaje(encrypted_message, private_key):
    d, n = private_key
    decrypted_message_as_int = pow(encrypted_message, d, n)
    decrypted_message = decrypted_message_as_int.to_bytes((decrypted_message_as_int.bit_length() + 7) 
    // 8, byteorder='big').decode('utf-8')
    return decrypted_message

# Se descifra el mensaje con el metodo tradicional
mensaje_descifrado = decifrar_mensaje(mensaje_cifrado, private_key)
print("Mensaje Descifrado:", mensaje_descifrado)

def decifrar_mensaje_crt(encrypted_message, private_key, primos):
    d, n = private_key
    p, q = primos
    
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inverse(q, p)
    
    m1 = pow(encrypted_message, dp, p)
    m2 = pow(encrypted_message, dq, q)
    
    h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    
    decrypted_message = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    return decrypted_message

# Se descifra el mensaje con el teorema del resto chino
mensaje_descifrado_crt = decifrar_mensaje_crt(mensaje_cifrado, private_key, primos)
print("Mensaje Descifrado con CRT:", mensaje_descifrado_crt)