import os

os.system('sage --preparse ../src/crypto99.sage')
os.system('mv ../src/crypto99.sage.py ./src_crypto99.py')

from src_crypto99 import *

#############
# Variables #
#############

n = 33 # Number of parties

#################
# Crypto99 PVSS #
#################

public_keys = [0 for _ in range(n)]
parties = [0 for _ in range(n)]
decrypted_shares_and_proofs = [0 for _ in range(n)]

for i in range(1,n+1):
    p = Party(i, n)
    public_keys[i-1] = p.broadcast_public_key()
    parties[i-1] = p

dealer = Dealer(public_keys, n)
total_time_dealer = time()
[commitments, encrypted_shares, dealer_proof] = dealer.share_stage()
total_time_dealer = time() - total_time_dealer
secret = fast_multiply(dealer.f(x=0), H)

total_time_party_verification = time()

for i in range(n):
    p = parties[i]
    decrypted_shares_and_proofs[i] = p.verification_stage(public_keys, commitments, encrypted_shares, dealer_proof)

total_time_party_verification = time() - total_time_party_verification
total_time_party_reconstruction = time()

for i in range(n):
    p = parties[i]
    reconstructed_secret = p.reconstruction_stage(decrypted_shares_and_proofs)
    assert secret == reconstructed_secret

total_time_party_reconstruction = time() - total_time_party_reconstruction

print("Total time for dealer: ", total_time_dealer, " seconds")
print("Average verification time for ", n, " parties: ", total_time_party_verification/n, " seconds")
print("Average reconstruction time for ", dealer.t+1, " parties: ", total_time_party_reconstruction/(dealer.t+1), " seconds")
