from cryptography.hazmat.primitives.asymmetric import dh as keygen
from Cryptodome.Hash import SHA3_256
from numpy.polynomial.polynomial import polyval

class Party:
    def __init__(self, party_number, generator, t, key_size):
        keygen_parameters = keygen.generate_parameters(generator=generator, key_size=key_size)
        self.__private_key = keygen_parameters.generate_private_key()
        self.number =  party_number
        self.t = t
        self.encrypted_share_pairs = None
        self.encrypted_share = None
        self.proof = None
        self.pub_keys = None

    def get_public_key(self):
        return self.__private_key.public_key()
        
    def receive_share_and_proof(self, encrypted_share_pairs, pi_share):
        self.encrypted_share_pairs = encrypted_share_pairs
        self.encrypted_share = self.encrypted_share_pairs[self.number]
        self.proof = pi_share

    def receive_public_keys(self, pub_keys):
        self.pub_keys = pub_keys

    def verify_shares(self):
        d = self.proof[0]
        z_x = self.proof[1]

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

    #######################
    ### PRIVATE METHODS ###
    #######################
        
    def __get_random_oracle_value(self, *args):
        data = ""

        for arg in args:
            data += arg

        binary_data = data.encode('utf-8')
        hash_class = SHA3_256.new()
        hash_class.update(binary_data)
        binary_hash = hash_class.digest()
        return int.from_bytes(binary_hash, "little")
        

    