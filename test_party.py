import unittest
from party import Party
from main import get_ed25519_domain_parameters

class TestParty(unittest.TestCase):
    def test_initialization(self):
        (p, G) = get_ed25519_domain_parameters()
        n = 3
        t = 2

        party1 = Party(0, G, n, t, p)
        party2 = Party(0, G, n, t, p)

        assert party1.public_key*party2.private_key == party2.public_key*party1.private_key
    
    
    

if __name__ == '__main__':
    unittest.main()