import random
from math import gcd
from typing import Tuple, NamedTuple

class RSAKey(NamedTuple):
    n: int
    e: int  # Public key
    d: int  # Private key

def is_prime(n: int, k: int = 5) -> bool:
    # Miller-Rabin primality test
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n

def mod_inverse(e: int, phi: int) -> int:
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, d, _ = extended_gcd(e, phi)
    return d % phi

def generate_keypair(bits: int = 1024) -> Tuple[RSAKey, RSAKey]:
    # Generate two distinct primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public exponent (e)
    e = 65537 
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)

    # Calculate private exponent (d)
    d = mod_inverse(e, phi)

    public_key = RSAKey(n=n, e=e, d=0)
    private_key = RSAKey(n=n, e=e, d=d)

    return public_key, private_key

def encrypt(message: int, public_key: RSAKey) -> int:
    """Encrypt a message using RSA public key"""
    return pow(message, public_key.e, public_key.n)

def decrypt(ciphertext: int, private_key: RSAKey) -> int:
    """Decrypt a message using RSA private key"""
    return pow(ciphertext, private_key.d, private_key.n)

def sign(message: int, private_key: RSAKey) -> int:
    """Sign a message using RSA private key"""
    return pow(message, private_key.d, private_key.n)

def verify_signature(message: int, signature: int, public_key: RSAKey) -> bool:
    """Verify a signature using RSA public key"""
    return pow(signature, public_key.e, public_key.n) == message

# Utilities
def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes"""
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

# Convert bytes to integer
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

# Convert RSA key 
def save_key_to_pem(key: RSAKey, is_private: bool = False) -> str:
    key_type = "RSA PRIVATE KEY" if is_private else "RSA PUBLIC KEY"
    
    key_data = f"{key.n},{key.e},{key.d if is_private else 0}"
    import base64
    encoded = base64.b64encode(key_data.encode()).decode()
    return f"-----BEGIN {key_type}-----\n{encoded}\n-----END {key_type}-----"

# Load RSA key
def load_key_from_pem(pem_str: str) -> RSAKey:
    import base64
    lines = pem_str.strip().split('\n')
    key_data = base64.b64decode(lines[1]).decode()
    n, e, d = map(int, key_data.split(','))
    return RSAKey(n=n, e=e, d=d)