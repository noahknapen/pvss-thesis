import unittest
from unittest.mock import Mock
from numpy.polynomial.polynomial import Polynomial
from dealer import Dealer
from party import Party
from main import create_generator_and_prime_pair

class TestInteraction(unittest.TestCase):
    def test_init(self):
        p = 11
        q = 5
        (g, _) = create_generator_and_prime_pair((p,q))
        n = 3
        t = 2
        party_list = []

        for i in range(1, n+1):
            party_list.append(Party(i, g, n, t, q))
        
        dealer = Dealer(n, t, q, g, party_list)
        # dealer.share_secret(2)
        (coeffs, f_x) = dealer.create_polynomial(2)
        assert type(coeffs) == list
        for coeff in coeffs:
            assert type(coeff) == int
        assert len(coeffs) == t+1
        assert type(f_x) == Polynomial

        encrypted_share_pairs = dealer.generate_encrypted_shares(coeffs)
        assert type(encrypted_share_pairs) == list
        for (index, enc_share) in encrypted_share_pairs:
            assert type(index) == int
            assert type(enc_share) == int

        pi_share = dealer.pi_pdl(f_x, encrypted_share_pairs)
        assert type(pi_share) == tuple
        assert type(pi_share[0]) == int
        assert type(pi_share[1]) == Polynomial

        dealer.broadcast(encrypted_share_pairs, pi_share)
        for party in party_list:
            assert party.number == encrypted_share_pairs[party.number-1][0]
            assert party.encrypted_share_pairs == encrypted_share_pairs
            assert party.encrypted_share == encrypted_share_pairs[party.number-1][1]
            assert party.dealer_proof == pi_share

        for party in party_list:
            assert True == party.verify_encrypted_shares(party_list) #! This fails sometimes

        for party in party_list:
            dec_share = party.generate_decrypted_share()
            assert type(dec_share) == int

            share_proof = party.nizk_proof_for_dleq(dec_share)
            assert type(share_proof) == tuple
            assert type(share_proof[0]) == int
            assert type(share_proof[1]) == int

            party.broadcast((party.number, dec_share), share_proof)
        
        for party in party_list:
            assert len(party.unverified_share_pairs_and_proof) == len(party_list)
            party.verify_decrypted_shares()
            assert len(party.verified_share_pairs) == len(party_list)
        

if __name__ == '__main__':
    unittest.main()