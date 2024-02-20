from Cryptodome.Protocol.SecretSharing import Shamir
from Cryptodome.Protocol.SecretSharing import _Element
from Cryptodome.Random import get_random_bytes
from numpy.polynomial import Polynomial

class Dealer:
    def __init__(self, n, t, q, generator, pub_keys):
        self.n = n
        self.t = t
        self.q = q
        self.generator = generator
        self.pub_keys = pub_keys

    def share_secret(self, secret):
        (coefficients, polynomial) = self.__create_polynomial(secret)
        encrypted_shares = self.__generate_encrypted_shares(coefficients)
        pi_share = self.__pi_pdl(polynomial, self.pub_keys, encrypted_shares)
           
    
    #######################
    ### PRIVATE METHODS ###
    #######################

    def __create_polynomial(self, secret):
        # We create a polynomial with random coefficients in GF(2^128):
        #
        # p(x) = \sum_{i=0}^{k-1} c_i * x^i
        #
        # c_0 is the encoded secret
        #

        coeffs = [_Element(get_random_bytes(16)) for i in range(self.t - 1)] #? Should self.q be worked into this instead of just 16 bytes?
        coeffs.append(_Element(secret))

        polynomial = Polynomial(coeffs)

        return (coeffs, polynomial) 
 
    def __generate_encrypted_shares(self, coefficients):
        shares = self.__generate_shares(coefficients)
        encrypted_shares = self.__encrypt_shares(shares)
        return encrypted_shares
    
    def __generate_shares(self, coefficients):
        # Returns a list of n tuples containing the unique index (integer) and the share itself (16 bytes)

        def make_share(user, coeffs):
            idx = _Element(user)
            share = _Element(0)
            for coeff in coeffs:
                share = idx * share + coeff

            return share.encode()

        return [(i, make_share(i, coefficients)) for i in range(1, n+1)]
        
    def __encrypt_shares(self, shares):
        # Returns a list of n tuples containing the unique index (integer) and the encrypted share (integer)
        encrypted_shares = []
        
        for i in range(len(shares)):
            encrypted_shares.append((shares[i][0], self.__encrypt_share(shares[i][1], self.pub_keys[i])))

    def __encrypt_share(self, share, pub_key):
        # Returns the encrypted share (integer)
        pub_key_int = int.from_bytes(pub_key, "little")
        share_int = int.from_bytes(share, "little")
        return pow(pub_key_int, share_int)

    def __generate_polynomial(self, secret, shares):
        # Returns the polynomial used to generate the shares
        #? Is this the correct polynomial?
        int_shares = [int.from_bytes(share, "little") for _,share in shares]
        int_secret = int.from_bytes(secret, "little")
        polynomial = Polynomial([int_secret] + int_shares)
        self.__polynomial = polynomial


    def __pi_pdl(self, encrypted_shares): 
        pass
