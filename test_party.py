import unittest
from unittest.mock import Mock
from party import Party
from Cryptodome.Protocol.SecretSharing import _Element
from numpy.polynomial.polynomial import Polynomial 

class TestParty(unittest.TestCase):
    def test_initialization(self):
        party = Party(0, 2, 3, 7)
        self.assertEqual(party.public_key, pow(2, int(party.private_key), 7))
        self.assertIsInstance(party, Party)
    

if __name__ == '__main__':
    unittest.main()