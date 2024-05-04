import os

os.system('sage --preparse pi_s.sage')
os.system('mv pi_s.sage.py pi_s.py')

os.system('sage --preparse crypto99.sage')
os.system('mv crypto99.sage.py crypto99.py')

os.system('sage --preparse pi_s_evoting.sage')
os.system('mv pi_s_evoting.sage.py pi_s_evoting.py')

os.system('sage --preparse crypto99_evoting.sage')
os.system('mv crypto99_evoting.sage.py crypto99_evoting.py')

from pi_s import *
from crypto99 import *
from pi_s_evoting import *
from crypto99_evoting import *


class ComparisonMetric:
    def fixed_talliers_evoting_pvss_schemes(self):
        pi_s1 = Pi_sEvotingMetrics(9, 9)
        pi_s2 = Pi_sEvotingMetrics(17, 9)
        pi_s3 = Pi_sEvotingMetrics(33, 9)
        pi_s4 = Pi_sEvotingMetrics(65, 9)
        pi_s5 = Pi_sEvotingMetrics(81, 9)

        crypto_1 = Crypto99EvotingMetrics(9, 9)
        crypto_2 = Crypto99EvotingMetrics(17, 9)
        crypto_3 = Crypto99EvotingMetrics(33, 9)
        crypto_4 = Crypto99EvotingMetrics(65, 9)
        crypto_5 = Crypto99EvotingMetrics(81, 9)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.casting_time, pi_s2.casting_time, pi_s3.casting_time, pi_s4.casting_time, pi_s5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Casting stage', color='blue', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.casting_time, crypto_2.casting_time, crypto_3.casting_time, crypto_4.casting_time, crypto_5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Casting stage', color='red', marker='s')
        g.show()

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.vote_verification_time/9, pi_s2.vote_verification_time/17, pi_s3.vote_verification_time/33, pi_s4.vote_verification_time/65, pi_s5.vote_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Vote verification stage', color='blue', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.vote_verification_time/9, crypto_2.vote_verification_time/17, crypto_3.vote_verification_time/33, crypto_4.vote_verification_time/65, crypto_5.vote_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Vote verification stage', color='red', marker='s')
        h.show()

        k = Graphics()
        k += list_plot(list(zip([9, 17, 33, 65], [pi_s1.tally_verification_time/9, pi_s2.tally_verification_time/17, pi_s3.tally_verification_time/33, pi_s4.tally_verification_time/65, pi_s5.tally_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Tally verification stage', color='blue', marker='s')
        k += list_plot(list(zip([9, 17, 33, 65], [crypto_1.tally_verification_time/9, crypto_2.tally_verification_time/17, crypto_3.tally_verification_time/33, crypto_4.tally_verification_time/65, crypto_5.tally_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Tally verification stage', color='red', marker='s')
        k.show()

    def fixed_voters_evoting_pvss_schemes(self):
        pi_s1 = Pi_sEvotingMetrics(9, 9)
        pi_s2 = Pi_sEvotingMetrics(9, 17)
        pi_s3 = Pi_sEvotingMetrics(9, 33)
        pi_s4 = Pi_sEvotingMetrics(9, 65)
        pi_s5 = Pi_sEvotingMetrics(9, 81)

        crypto_1 = Crypto99EvotingMetrics(9, 9)
        crypto_2 = Crypto99EvotingMetrics(9, 17)
        crypto_3 = Crypto99EvotingMetrics(9, 33)
        crypto_4 = Crypto99EvotingMetrics(9, 65)
        crypto_5 = Crypto99EvotingMetrics(9, 81)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.casting_time, pi_s2.casting_time, pi_s3.casting_time, pi_s4.casting_time, pi_s5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Casting stage', color='blue', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.casting_time, crypto_2.casting_time, crypto_3.casting_time, crypto_4.casting_time, crypto_5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Casting stage', color='red', marker='s')
        g.show()

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.vote_verification_time/9, pi_s2.vote_verification_time/17, pi_s3.vote_verification_time/33, pi_s4.vote_verification_time/65, pi_s5.vote_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Vote verification stage', color='blue', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.vote_verification_time/9, crypto_2.vote_verification_time/17, crypto_3.vote_verification_time/33, crypto_4.vote_verification_time/65, crypto_5.vote_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Vote verification stage', color='red', marker='s')
        h.show()

        k = Graphics()
        k += list_plot(list(zip([9, 17, 33, 65], [pi_s1.tally_verification_time/9, pi_s2.tally_verification_time/17, pi_s3.tally_verification_time/33, pi_s4.tally_verification_time/65, pi_s5.tally_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Tally verification stage', color='blue', marker='s')
        k += list_plot(list(zip([9, 17, 33, 65], [crypto_1.tally_verification_time/9, crypto_2.tally_verification_time/17, crypto_3.tally_verification_time/33, crypto_4.tally_verification_time/65, crypto_5.tally_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=1, legend_label='Tally verification stage', color='red', marker='s')
        k.show()

    def base_pvss_schemes():
        # Take powers of 2 values
        pi_s1 = Pi_s_Metrics(9)
        pi_s2 = Pi_s_Metrics(17)
        pi_s3 = Pi_s_Metrics(33)
        pi_s4 = Pi_s_Metrics(65)
        pi_s5 = Pi_s_Metrics(81)

        crypto_1 = Crypto99Metrics(9)
        crypto_2 = Crypto99Metrics(17)
        crypto_3 = Crypto99Metrics(33)
        crypto_4 = Crypto99Metrics(65)
        crypto_5 = Crypto99Metrics(81)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.total_time_dealer, pi_s2.total_time_dealer, pi_s3.total_time_dealer, pi_s4.total_time_dealer, pi_s5.total_time_dealer])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Sharing stage', color='blue', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.total_time_dealer, crypto_2.total_time_dealer, crypto_3.total_time_dealer, crypto_4.total_time_dealer, crypto_5.total_time_dealer])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Sharing stage', color='red', marker='s')
        g.show()

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.total_time_party_verification/9, pi_s2.total_time_party_verification/17, pi_s3.total_time_party_verification/33, pi_s4.total_time_party_verification/65, pi_s5.total_time_party_verification/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=2.1, legend_label='Verification stage', color='blue', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.total_time_party_verification/9, crypto_2.total_time_party_verification/17, crypto_3.total_time_party_verification/33, crypto_4.total_time_party_verification/65, crypto_5.total_time_party_verification/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=2.1, legend_label='Verification stage', color='red', marker='s')
        h.show()

        k = Graphics()
        k += list_plot(list(zip([pi_s1.t+1, pi_s2.t+1, pi_s3.t+1, pi_s4.t+1], [pi_s1.total_time_party_reconstruction/(pi_s1.t+1), pi_s2.total_time_party_reconstruction/(pi_s2.t+1), pi_s3.total_time_party_reconstruction/(pi_s3.t+1), pi_s4.total_time_party_reconstruction/(pi_s4.t+1), pi_s5.total_time_party_reconstruction/(pi_s5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Reconstruction stage', color='blue', marker='s')
        k += list_plot(list(zip([crypto_1.t+1, crypto_2.t+1, crypto_3.t+1, crypto_4.t+1, crypto_5.t+1], [crypto_1.total_time_party_reconstruction/(crypto_1.t+1), crypto_2.total_time_party_reconstruction/(crypto_2.t+1), crypto_3.total_time_party_reconstruction/(crypto_3.t+1), crypto_4.total_time_party_reconstruction/(crypto_4.t+1), crypto_5.total_time_party_reconstruction/(crypto_5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Reconstruction stage', color='red', marker='s')
        k.show()


ComparisonMetric.base_pvss_schemes() 