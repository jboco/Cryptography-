import collections
import random

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp224r1',
    # Field characteristic.
    p=0xffffffffffffffffffffffffffffffff000000000000000000000001,
    # Curve coefficients.
    a=0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe,
    b=0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
    # Base point.
    g=(0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34),
    # Subgroup order.
    n=0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
    # Subgroup cofactor.
    h=1,
)

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point
    #return (y * y - x * x * x - curve.a * x * x - x) % curve.p == 0
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


# Keypair generation and ECDHE ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


print('Curve:', curve.name)

# Alice generates her own keypair.
alice_private_key, alice_public_key = make_keypair()
print("Alice's private key:", hex(alice_private_key))
print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key))

# Bob generates his own key pair.
bob_private_key, bob_public_key = make_keypair()
print("Bob's private key:", hex(bob_private_key))
print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key))

# Alice and Bob exchange their public keys and calculate the shared secret.
s1 = scalar_mult(alice_private_key, bob_public_key)
s2 = scalar_mult(bob_private_key, alice_public_key)
assert s1 == s2

print('Shared secret: (0x{:x}, 0x{:x})'.format(*s1))
