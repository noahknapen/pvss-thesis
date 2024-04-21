import os

os.system('sage --preparse ../src/pi_s.sage')
os.system('mv ../src/pi_s.sage.py ./src_pi_s.py')

from src_pi_s import *

#############
# Variables #
#############

n = 33 # Number of parties #! n should be odd in majority honest setting

#############
# pi_s PVSS #
#############

public_keys = [0 for _ in range(n)]
parties = [0 for _ in range(n)]
decrypted_shares_and_proofs = [0 for _ in range(n)]

for i in range(1,n+1):
    p = Party(i, n)
    public_keys[i-1] = p.broadcast_public_key()
    parties[i-1] = p

dealer = Dealer(public_keys, n)
total_time_dealer = time()
[encrypted_shares, dealer_proof] = dealer.share_stage()
total_time_dealer = time() - total_time_dealer
secret = fast_multiply(dealer.f(x=0), G)

total_time_party_verification = time()

for i in range(n):
    p = parties[i]
    decrypted_shares_and_proofs[i] = p.verification_stage(public_keys, encrypted_shares, dealer_proof)

total_time_party_verification = time() - total_time_party_verification
total_time_party_reconstruction = time()

for i in range(n):
    p = parties[i]
    reconstructed_secret = p.reconstruction_stage(decrypted_shares_and_proofs)
    assert secret == reconstructed_secret

total_time_party_reconstruction = time() - total_time_party_reconstruction

print("Total time for dealer: ", total_time_dealer, " seconds")
print("Total verification time for ", n, " parties: ", total_time_party_verification/n, " seconds") #TODO This includes ...
print("Total reconstruction time for ", dealer.t+1, " parties: ", total_time_party_reconstruction/(dealer.t+1), " seconds") #TODO This includes ...
