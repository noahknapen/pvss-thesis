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
        (pi_s_sharing128, pi_s_verification128) = Pi_s_Metrics(128)
        print("Values for n=128--------------------------")
        print("PI_s: sharing: {pi_s_sharing128} and verification: {pi_s_verification128}")
        (crypto99_sharing128, crypto99_verification128) = Crypto99Metrics(128)
        print("Schoenmakers: sharing: {crypto99_sharing128} and verification: {crypto99_verification128}")


        (pi_s_sharing256, pi_s_verification256) = Pi_s_Metrics(256)
        print("Values for n=256--------------------------")
        print("PI_s: sharing: {pi_s_sharing256} and verification: {pi_s_verification256}")
        (crypto99_sharing256, crypto99_verification256) = Crypto99Metrics(256)
        print("Schoenmakers: sharing: {crypto99_sharing256} and verification: {crypto99_verification256}")


        (pi_s_sharing512, pi_s_verification512)= Pi_s_Metrics(512)
        print("Values for n=512--------------------------")
        print("PI_s: sharing: {pi_s_sharing512} and verification: {pi_s_verification512}")

        (pi_s_sharing1024, pi_s_verification1024) = Pi_s_Metrics(1024)
        print("Values for n=1024--------------------------")
        print("PI_s: sharing: {pi_s_sharing1024} and verification: {pi_s_verification1024}")


        (crypto99_sharing512, crypto99_verification512)= Crypto99Metrics(512)
        print("Values for Schoenmakers for n=512----------")
        print("Schoenmakers: sharing: {crypto99_sharing512} and verification: {crypto99_verification512}")


ComparisonMetric.base_schemes()