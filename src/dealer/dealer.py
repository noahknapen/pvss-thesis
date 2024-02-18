from Cryptodome.Protocol.SecretSharing import Shamir
from numpy.polynomial import Polynomial

class Dealer:
    def __init__(self, n, t, generator, pub_keys):
        self.n = n
        self.t = t
        self.generator = generator
        self.pub_keys = pub_keys


