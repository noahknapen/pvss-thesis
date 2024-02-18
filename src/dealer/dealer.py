from Cryptodome.Protocol.SecretSharing import Shamir
from numpy.polynomial import Polynomial

class Dealer:
    def __init__(self, n, t, generator, pub_keys):
        self.n = n
        self.t = t
        self.generator = generator
        self.pub_keys = pub_keys

    def share_stage(self, secret):
        shares = self.__generate_encrypted_shares(secret)
        pi_share = self.__pi_pdl()
           
    
    #######################
    ### PRIVATE METHODS ###
    #######################
 
    def __generate_encrypted_shares(self, secret):
        shares = self.__generate_shares(secret)
        self.__generate_polynomial(secret, shares)
        encrypted_shares = self.__encrypt_shares(shares)
        return encrypted_shares
    
    def __generate_shares(self, secret):
        # Returns a list of n tuples containing the unique index (integer) and the share itself (16 bytes)
        return Shamir.split(self.t, self.n, secret)
        
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
