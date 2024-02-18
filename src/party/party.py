from cryptography.hazmat.primitives.asymmetric import dh

class Party:
    def __init__(self, generator, key_size):
        dh_parameters = dh.generate_parameters(generator=generator, key_size=key_size) #TODO: Change generator and key_size to something more secure
        self.__private_key = dh_parameters.generate_private_key()


    def get_public_key(self):
        return self.__private_key.public_key()
        
