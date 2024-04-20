import os

os.system('sage --preparse ../src/crypto99_evoting.sage')
os.system('mv ../src/crypto99_evoting.sage.py ./src_crypto99_evoting.py')

from src_crypto99_evoting import *

m = 1 # Number of voters (dealers)
n = 7 # Number of talliers (parties)
public_keys = [0 for _ in range(n)]
parties = [0 for _ in range(n)]
dealers = [0 for _ in range(m)]
enc_shares = [0 for _ in range(m)]
enc_votes = [0 for _ in range(m)]
vote_proofs = [0 for _ in range(m)]

for i in range(1,n+1):
    p = Tallier(i, m, n)
    parties[i-1] = p
    public_keys[i-1] = p.broadcast_public_key()

for i in range(m):
    d = Voter(public_keys, n)
    dealers[i] = d
    [commitments, encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
    enc_shares[i] = encrypted_shares
    enc_votes[i] = encrypted_vote
    vote_proofs[i] = vote_proof

b = BulletinBoard()
assert b.verify_adapted_dleqs(commitments[0], enc_votes, vote_proofs)