import collections


Point = collections.namedtuple('Point', ['x', 'y'])


def get_identity_point():
    return Point(float('inf'), float('inf'))


def is_identity_point(P):
    return P == get_identity_point()
