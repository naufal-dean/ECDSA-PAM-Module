import base64
import re

from . import Point, ECC


a = 0
b = 7
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class LoadKeyError(Exception):
    pass


class ParseKeyError(Exception):
    pass


class SECP256K1(ECC):
    def __init__(self, d=None, Q=None):
        super(SECP256K1, self).__init__(a, b, p, n=n, G=G, auto_gen_group=False, auto_gen_key=False)
        self.d = d
        self.Q = Q

    def pub_key_repr(self):
        assert self.Q is not None
        rep = '-----BEGIN SECP256K1 PUBLIC KEY-----\n'
        rep += str(self.Q.x) + '\n' + str(self.Q.y) + '\n'
        rep += '-----END SECP256K1 PUBLIC KEY-----\n'
        return rep

    def pri_key_repr(self):
        assert self.d is not None
        rep = '-----BEGIN SECP256K1 PRIVATE KEY-----\n'
        rep += str(self.d) + '\n'
        rep += '-----END SECP256K1 PRIVATE KEY-----\n'
        return rep

    @classmethod
    def parse_repr(cls, rep):
        try:
            pattern = r'^-----BEGIN SECP256K1 (.*) KEY-----\n'
            pattern += r'(.*)\n'
            pattern += r'-----END SECP256K1 \1 KEY-----\n'
            match = re.findall(pattern, rep, re.DOTALL)[0]
            # create curve object
            curve = cls()
            # add public/private key
            if match[0] == 'PUBLIC':
                curve.Q = Point(*list(map(int, match[1].split('\n')))[:2])
            elif match[0] == 'PRIVATE':
                curve.d = int(match[1])
                curve.Q = curve.multiply(curve.d, curve.G)
            else:
                raise Exception('Invalid key file')
        except Exception as e:
            raise ParseKeyError()
        else:
            return curve

    def save_file(self, filename):
        with open(filename + '.pri', 'wb') as pri:
            pri.write(self.pri_key_repr())
        with open(filename + '.pub', 'wb') as pub:
            pub.write(self.pub_key_repr())

    @classmethod
    def load_key(cls, filename):
        try:
            with open(filename, 'rb') as f:
                key = f.read()
            curve = cls.parse_repr(key)
        except Exception as e:
            raise LoadKeyError()
        else:
            return curve
