import collections
import random
import hashlib

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0

def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 ==- y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * pow(2 * y1,-1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * pow(x1 - x2, -1, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result

def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key

def hash_truncate_message(message):
    """Returns the truncated SHA512 hash of the message."""
    message_hash = hashlib.sha512(message).digest()
    e = int.from_bytes(message_hash, 'big')
    # hash is truncated to fit curve order size
    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    # In case hash size is lower than curve order size, refer to FIPS 186-4 
    z = e >> (e.bit_length() - curve.n.bit_length())

    assert z.bit_length() <= curve.n.bit_length()

    return z

def sign_message(k, private_key, message):
    z = hash_truncate_message(message)

    r = 0
    s = 0

    while not r or not s:
        
        x, y = scalar_mult(k, curve.g)

        r = x % curve.n
        s = ((z + r * private_key) * pow(k, -1, curve.n)) % curve.n

    return (r, s)

def verify_signature(public_key, message, signature):
    z = hash_truncate_message(message)

    r, s = signature

    w = pow(s, -1, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'

private, public = make_keypair()
print("Private key:", hex(private))
print("Public key: (0x{:x}, 0x{:x})".format(*public))

#Nonce is constant and re-used
k = random.randrange(1, curve.n)
print('The nonce is k=', k)

msg1 = b'First signed message'
signature1 = sign_message(k, private, msg1)

print()
print('Message:', msg1)
print('Signature: (0x{:x}, 0x{:x})'.format(*signature1))
print('Verification:', verify_signature(public, msg1, signature1))

msg2 = b'Second signed message with same nonce!'
signature2 = sign_message(k, private, msg2)
print()
print('Message:', msg2)
print('Signature: (0x{:x}, 0x{:x})'.format(*signature2))
print('Verification:', verify_signature(public, msg2, signature2))

# Attacker computes the re-used nonce and private key 
z1 = hash_truncate_message(msg1)
z2= hash_truncate_message(msg2)
r1, s1 = signature1
r2, s2 = signature2 
k = ((z1-z2)*(pow((s1-s2),-1, curve.n)))%curve.n
print('The computed nonce is k=', k)

private = (pow(r1,-1,curve.n)*(s1*k-z1))%curve.n
print("The computed private key:", hex(private))
