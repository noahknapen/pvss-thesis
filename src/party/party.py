from cryptography.hazmat.primitives.asymmetric import dh as keygen
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random import get_random_bytes
from numpy.polynomial.polynomial import polyval
import math

class Party:
    def __init__(self, party_number, generator, t, parties, key_size):
        keygen_parameters = keygen.generate_parameters(generator=generator, key_size=key_size)
        self.__private_key = keygen_parameters.generate_private_key()
        self.public_key = self.__private_key.public_key()
        self.generator = generator
        self.number =  party_number
        self.t = t
        self.parties = parties
        self.encrypted_share_pairs = None
        self.encrypted_share = None
        self.dealer_proof = None
        self.pub_keys = None
        self.decrypted_share_pairs = []

    def get_public_key(self):
        return self.public_key
        
    def receive_shares_and_dealer_proof(self, encrypted_share_pairs, pi_share):
        self.encrypted_share_pairs = encrypted_share_pairs
        self.encrypted_share = self.encrypted_share_pairs[self.number]
        self.dealer_proof = pi_share

    def receive_public_keys(self, pub_keys):
        self.pub_keys = pub_keys
    
    def receive_decrypted_share_and_proof(self, decrypted_share_pair, share_proof):
        if share_proof: #TODO: implement verification of proof
            self.decrypted_share_pairs.append(decrypted_share_pair)

    def verify_shares(self):
        d = self.dealer_proof[0]
        z_x = self.dealer_proof[1]

        if z_x.degree() != self.t:
            return False

        z_x_coeffs = z_x.coef
        encrypted_r_x = []

        for i in range(0, self.n):
            z_i = polyval(z_x_coeffs, i+1)
            encrypted_z_i = pow(self.parties[i].get_public_key, z_i)
            divider = pow(self.encrypted_share_pairs[i],d)
            encrypted_r_x.append(encrypted_z_i / divider)
            
        args = [encrypted_share_pair[1] for encrypted_share_pair in self.encrypted_share_pairs] + encrypted_r_x
        d_test = self.__get_random_oracle_value(args)

        return d == d_test

    def publish_decrypted_share_and_proof(self):
        share = pow(self.encrypted_share, 1/self.__private_key)
        share_proof = self.__nizk_proof_for_dleq(share)
        self.__broadcast((self.number, share), share_proof)

    def reconstruct_secret(self):
        # Assume self.decrypted_share_pairs is an ordered list of tuples (i, share)
        exponent = 0

        for i in range(0, self.t+1):
            decrypted_share = self.decrypted_share_pairs[i][1]
            lagrange_coeff = self.__compute_lagrange_coefficient(i)
            exponent += lagrange_coeff * decrypted_share

        return pow(self.generator, exponent)

    #######################
    ### PRIVATE METHODS ###
    #######################

    def __compute_lagrange_coefficient(self, i):
        numerator = 1
        denominator = 1

        for j in range(0, self.t+1):
            if j != i:
                numerator *= j
                denominator *= j - i

        return numerator / denominator
        
    def __get_random_oracle_value(self, *args):
        data = ""

        for arg in args:
            data += arg

        binary_data = data.encode('utf-8')
        hash_class = SHA3_256.new()
        hash_class.update(binary_data)
        binary_hash = hash_class.digest()
        return int.from_bytes(binary_hash, "little")
        
    def __nizk_proof_for_dleq(self, decrypted_share):
        r = get_random_bytes(math.floor(math.log(self.q, 2))+1)
        d = self.__get_random_oracle_value(self.public_key, self.encrypted_share, pow(self.generator, r), pow(decrypted_share, r))
        z = r + d*self.__private_key

    def __broadcast(self, decrypted_share, share_proof):
        for party in self.parties:
            party.receive_decrypted_share_and_proof(decrypted_share, share_proof)
    