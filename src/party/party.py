from cryptography.hazmat.primitives.asymmetric import dh as keygen

class Party:
    def __init__(self, party_number, generator, key_size):
        keygen_parameters = keygen.generate_parameters(generator=generator, key_size=key_size)
        self.__private_key = keygen_parameters.generate_private_key()
        self.number =  party_number
        self.encrypted_share_pairs = None
        self.encrypted_share = None
        self.proof = None


    def get_public_key(self):
        return self.__private_key.public_key()
        
    def receive_share_and_proof(self, encrypted_share_pairs, pi_share):
        self.encrypted_share_pairs = encrypted_share_pairs
        self.encrypted_share = self.encrypted_share_pairs[self.number]
        self.proof = pi_share
