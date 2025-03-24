import os

os.system('sage --preparse pi_s.sage')
os.system('mv pi_s.sage.py pi_s.py')

os.system('sage --preparse crypto99.sage')
os.system('mv crypto99.sage.py crypto99.py')

os.system('sage --preparse ACNS.sage')
os.system('mv ACNS.sage.py ACNS.py')

os.system('sage --preparse pi_s_evoting.sage')
os.system('mv pi_s_evoting.sage.py pi_s_evoting.py')

os.system('sage --preparse crypto99_evoting.sage')
os.system('mv crypto99_evoting.sage.py crypto99_evoting.py')

from pi_s import *
from crypto99 import *
from ACNS import *
from pi_s_evoting import *
from crypto99_evoting import *

class ComparisonMetric:
    def base_schemes():
        (pi_s_sharing129, pi_s_verification129) = Pi_s_Metrics.run(129)
        print("Values for n=129--------------------------")
        print("PI_s: sharing: {pi_s_sharing129} and verification: {pi_s_verification129}")
        (crypto99_sharing129, crypto99_verification129) = Crypto99Metrics.run(129)
        print("Schoenmakers: sharing: {crypto99_sharing129} and verification: {crypto99_verification129}")


        (pi_s_sharing257, pi_s_verification257) = Pi_s_Metrics.run(257)
        print("Values for n=256--------------------------")
        print("PI_s: sharing: {pi_s_sharing257} and verification: {pi_s_verification257}")
        (crypto99_sharing257, crypto99_verification257) = Crypto99Metrics(257)
        print("Schoenmakers: sharing: {crypto99_sharing257} and verification: {crypto99_verification257}")


        (pi_s_sharing513, pi_s_verification513)= Pi_s_Metrics.run(513)
        print("Values for n=513--------------------------")
        print("PI_s: sharing: {pi_s_sharing513} and verification: {pi_s_verification513}")

        (pi_s_sharing1025, pi_s_verification1025) = Pi_s_Metrics.run(1025)
        print("Values for n=1025--------------------------")
        print("PI_s: sharing: {pi_s_sharing1025} and verification: {pi_s_verification1025}")


        (crypto99_sharing513, crypto99_verification513)= Crypto99Metrics.run(513)
        print("Values for Schoenmakers for n=513----------")
        print("Schoenmakers: sharing: {crypto99_sharing513} and verification: {crypto99_verification513}")


ComparisonMetric.base_schemes()