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
    def evoting_schemes():
        (pi_s_casting129, pi_s_verification129, pi_s_tallying129) = Pi_sEvotingMetrics.run(3, 65)
        print("Values in seconds for n=129--------------------------")
        print("PI_s: casting:" + str(pi_s_casting129) + ", verification: " + str(pi_s_verification129) + " and tallying: " + str(pi_s_tallying129))
        (crypto99_casting129, crypto99_verification129, crypto99_tallying129) = Crypto99EvotingMetrics.run(3, 65)
        print("Schoenmakers: casting: " + str(crypto99_casting129) + ", verification: " + str(crypto99_verification129) + " and tallying: " + str(crypto99_tallying129))


        (pi_s_casting257, pi_s_verification257, pi_s_tallying257) = Pi_sEvotingMetrics.run(3, 257)
        print("Values in seconds for n=256--------------------------")
        print("PI_s: casting: " + str(pi_s_casting257)  + ", verification: " + str(pi_s_verification257) + " and tallying: " + str(pi_s_tallying257))
        (crypto99_casting257, crypto99_verification257, crypto99_tallying257) = Crypto99EvotingMetrics.run(3, 257)
        print("Schoenmakers: casting: " + str(crypto99_casting257) + ", verification: " + str(crypto99_verification257) + " and tallying: " + str(crypto99_tallying257))


        (pi_s_casting513, pi_s_verification513, pi_s_tallying513)= Pi_sEvotingMetrics.run(3, 513)
        print("Values in seconds for n=513--------------------------")
        print("PI_s: casting: " + str(pi_s_casting513)  + ", verification: " + str(pi_s_verification513) + " and tallying: " + str(pi_s_tallying513))

        (pi_s_casting1025, pi_s_verification1025, pi_s_tallying1025) = Pi_sEvotingMetrics.run(3, 1025)
        print("Values in seconds for n=1025--------------------------")
        print("PI_s: casting: " + str(pi_s_casting1025)  + ", verification: " + str(pi_s_verification1025) + " and tallying: " + str(pi_s_tallying1025))


        (crypto99_casting513, crypto99_verification513, crypto99_tallying513) = Crypto99EvotingMetrics.run(3, 513)
        print("Values in seconds for Schoenmakers for n=513----------")
        print("Schoenmakers: casting: " + str(crypto99_casting513) +  ", verification: " + str(crypto99_verification513) + " and tallying: " + str(crypto99_tallying513))

ComparisonMetric.evoting_schemes()