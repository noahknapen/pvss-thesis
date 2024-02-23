from cryptography.hazmat.primitives.asymmetric import dh as keygen

class Party:
    def __init__(self, generator, key_size):
        keygen_parameters = keygen.generate_parameters(generator=generator, key_size=key_size)
        self.__private_key = keygen_parameters.generate_private_key()


    def get_public_key(self):
        return self.__private_key.public_key()
        
