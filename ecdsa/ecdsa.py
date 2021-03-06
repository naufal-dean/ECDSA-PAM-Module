import random

from . import Point, is_identity_point, ECC
from .util import mod_inverse


class ValidationError(Exception):
    pass


class ECDSA(object):
    def __init__(self, curve):
        assert isinstance(curve, ECC)

        self.curve = curve

    def sign(self, hash):
        # initial check if the private key contained in the curve
        if self.curve.d is None:
            raise Exception("Private key d is needed to sign message")
        # calculate z: L_n leftmost byte of hash, n is bit_length of self.curve.n
        z = hash >> max(0, (hash.bit_length() - self.curve.n.bit_length()))
        while True:
            # generate random number k from [1, n - 1]
            k = random.randrange(1, self.curve.n)
            # calculate point (x1, y1) = k x G
            x1, y1 = self.curve.multiply(k, self.curve.G)
            # check 1
            r = x1 % self.curve.n
            if r == 0: continue
            # check 2
            k_inv = mod_inverse(k, self.curve.n)
            s = (k_inv * (z + (r * self.curve.d))) % self.curve.n
            if s == 0: continue
            # valid
            break
        return (r, s)

    def verify(self, hash, r, s):
        # check r and s in [1, n - 1]
        if not all(list((1 <= r, s < self.curve.n))):
            return False
        # calculate z: L_n leftmost byte of hash, n is bit_length of self.curve.n
        z = hash >> max(0, (hash.bit_length() - self.curve.n.bit_length()))
        # calculate u1 = zs^-1 and u2 = rs^-1
        # s_inv = pow(s, -1, self.curve.n)
        s_inv = mod_inverse(s, self.curve.n)
        u1 = (z * s_inv) % self.curve.n
        u2 = (r * s_inv) % self.curve.n
        # calculate point (x1, y1) = u1 x G + u2 x Q
        temp1 = self.curve.multiply(u1, self.curve.G)
        temp2 = self.curve.multiply(u2, self.curve.Q)
        x1, y1 = self.curve.add_points(temp1, temp2)
        # check if (x1, y1) == O
        if is_identity_point(Point(x1, y1)):
            return False
        # check r == x1 mod n
        if r == x1 % self.curve.n:
            return True
        else:
            raise ValidationError()
