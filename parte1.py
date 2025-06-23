import random
from hashlib import sha3_256
import os

# Teste de primalidade de Miller-Rabin
def miller_rabin(n, reps=40):
    # True significa ser provavelmente primo
    if n == 2 or n == 3:
        return True
    elif n <= 1 or n % 2 == 0:
        return False

    # Escrevendo (n-1) como (2^s * d)
    s = 0
    d = n - 1

    while d % 2 == 0:
        s += 1
        d //= 2

    
    for _ in range(reps):
        # Escolhendo a base 'a' com 1 < a < (n-1)
        a = random.randrange(2, n - 1)

        # Primeira condição -> a^d (mod n) 
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue
        
        # Segunda condição
        for i in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
        
    return True

# Função que gera primos grandes e indivisíveis por e = 65537.
def generate_primes(e=65537):
    while True:
        p = random.getrandbits(1024)
        p = p | ((1 << (1023)) | 1)
        if miller_rabin(p) and p % e != 0:
            return p

# Algoritmo euclidiano estendido para obter os coeficientes de Bézout    
def eea(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = eea(b % a, a)
    return (g, x - (b // a) * y, y)

# Função para computar o inverso modular de a mod b
def modular_inverse(a, b):
    g, x, _ = eea(a, b)
    if g != 1:
        raise Exception("Inverso modular não existe")
    return x % b

# Geração de chaves (pública e privada) - RSA
def generate_rsa_keys():
    # Gerando primos p e q
    p = generate_primes()
    q = generate_primes()

    # Obtendo n e z a partir de p e q
    n = p * q
    z = (p - 1) * (q - 1)

    # O 'e' é fixo, pois é um primo pequeno, aumentando a eficiência
    e = 65537

    # 'd' é um número tal que ed = 1 mod(z). Logo, 'd' é o inverso modular de z.
    # Dessa forma, usamos o Algoritmo Euclidiano Estendido (dentro da função modular_inverse)
    # para obter d.
    d = modular_inverse(e, z)

    public_key = (e, n)
    private_key = (d, n)

    return (public_key, private_key)

# Função de Geração de Máscaras - MGF1
def mgf1(seed: bytes, length: int, hash_func=sha3_256) -> bytes:
    counter = 0
    output = b''
    while len(output) < length:
        C = counter.to_bytes(4, byteorder='big')
        output += hash_func(seed + C).digest()
        counter += 1
    return output[:length]

# Codifica a mensagem com OAEP
def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_func=sha3_256) -> bytes:
    hLen = hash_func().digest_size
    mLen = len(message)

    if mLen > k - 2 * hLen - 2:
        raise ValueError("Mensagem muito longa")

    lHash = hash_func(label).digest()
    ps = b'\x00' * (k - mLen - 2 * hLen - 2)
    db = lHash + ps + b'\x01' + message
    seed = os.urandom(hLen)

    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    maskedDB = bytes(x ^ y for x, y in zip(db, dbMask))

    seedMask = mgf1(maskedDB, hLen, hash_func)
    maskedSeed = bytes(x ^ y for x, y in zip(seed, seedMask))

    return b'\x00' + maskedSeed + maskedDB

# Decodifica a mensagem com OAEP
def oaep_decode(encoded: bytes, k: int, label: bytes = b"", hash_func=sha3_256) -> bytes:
    hLen = hash_func().digest_size

    if len(encoded) != k or k < 2 * hLen + 2:
        raise ValueError("Decodificação inválida")

    Y = encoded[0]
    maskedSeed = encoded[1:hLen + 1]
    maskedDB = encoded[hLen + 1:]

    seedMask = mgf1(maskedDB, hLen, hash_func)
    seed = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))

    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    db = bytes(x ^ y for x, y in zip(maskedDB, dbMask))

    lHash = hash_func(label).digest()
    lHash_ = db[:hLen]

    if lHash != lHash_:
        raise ValueError("lHash inválido")

    rest = db[hLen:]
    sep_index = rest.find(b'\x01')
    if sep_index == -1:
        raise ValueError("0x01 não encontrado após padding")

    return rest[sep_index + 1:]

# Criptografa pelo RSA a mensagem codificada com OAEP
def rsa_encrypt_oaep(message: bytes, pubkey):
    e, n = pubkey
    k = (n.bit_length() + 7) // 8
    padded = oaep_encode(message, k)
    m_int = int.from_bytes(padded, byteorder='big')
    c = pow(m_int, e, n)
    return c

# Descriptografa o pacote criptografado pelo RSA codificado com OAEP usando a chave pública
def rsa_decrypt_oaep(ciphertext: int, privkey):
    d, n = privkey
    k = (n.bit_length() + 7) // 8
    m_int = pow(ciphertext, d, n)
    padded = m_int.to_bytes(k, byteorder='big')
    message = oaep_decode(padded, k)
    return message

# if __name__ == "__main__":
#     pub, priv = generate_rsa_keys()
#     mensagem = b"Seguranca computacional - Projeto 2"

#     cifra = rsa_encrypt_oaep(mensagem, pub)
#     print(f"Cifra: {cifra}")

#     decifrada = rsa_decrypt_oaep(cifra, priv)
#     print(f"Decifrada: {decifrada}")
