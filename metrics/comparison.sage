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
    def fixed_talliers_evoting_pvss_schemes():
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
        g += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.casting_time, pi_s2.casting_time, pi_s3.casting_time, pi_s4.casting_time, pi_s5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=5, legend_label='Pi_s', color='blue', marker='s', title='Casting stage')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.casting_time, crypto_2.casting_time, crypto_3.casting_time, crypto_4.casting_time, crypto_5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=5, legend_label='Schoenmakers99', color='red', marker='s', title='Casting stage')
        g.show()

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.vote_verification_time/9, pi_s2.vote_verification_time/17, pi_s3.vote_verification_time/33, pi_s4.vote_verification_time/65, pi_s5.vote_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.02, legend_label='Pi_s', color='blue', marker='s', title='Vote verification stage')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.vote_verification_time/9, crypto_2.vote_verification_time/17, crypto_3.vote_verification_time/33, crypto_4.vote_verification_time/65, crypto_5.vote_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.02, legend_label='Schoenmakers99', color='red', marker='s', title='Vote verification stage')
        h.show()

        k = Graphics()
        k += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.share_verification_time/9, pi_s2.share_verification_time/9, pi_s3.share_verification_time/9, pi_s4.share_verification_time/9, pi_s5.share_verification_time/9])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=4, legend_label='Pi_s', color='blue', marker='s', title='Share verification stage')
        k += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.share_verification_time/9, crypto_2.share_verification_time/9, crypto_3.share_verification_time/9, crypto_4.share_verification_time/9, crypto_5.share_verification_time/9])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=4, legend_label='Schoenmakers99', color='red', marker='s', title='Share verification stage')
        k.show()

        l = Graphics()
        l += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.tally_reconstruction_time/(pi_s1.t+1), pi_s2.tally_reconstruction_time/(pi_s2.t+1), pi_s3.tally_reconstruction_time/(pi_s3.t+1), pi_s4.tally_reconstruction_time/(pi_s4.t+1), pi_s5.tally_reconstruction_time/(pi_s5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.1, legend_label='Pi_s', color='blue', marker='s', title='Vote tallying stage')
        l += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.tally_reconstruction_time/(crypto_1.t+1), crypto_2.tally_reconstruction_time/(crypto_2.t+1), crypto_3.tally_reconstruction_time/(crypto_3.t+1), crypto_4.tally_reconstruction_time/(crypto_4.t+1), crypto_5.tally_reconstruction_time/(crypto_5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.1, legend_label='Schoenmakers99', color='red', marker='s', title='Vote tallying stage')
        l.show()

    def fixed_voters_evoting_pvss_schemes():
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
        g += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.casting_time, pi_s2.casting_time, pi_s3.casting_time, pi_s4.casting_time, pi_s5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=5, legend_label='Pi_s', color='blue', marker='s', title='Casting stage')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.casting_time, crypto_2.casting_time, crypto_3.casting_time, crypto_4.casting_time, crypto_5.casting_time])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=5, legend_label='Schoenmakers99', color='red', marker='s', title='Casting stage')
        g.show()

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.vote_verification_time/9, pi_s2.vote_verification_time/9, pi_s3.vote_verification_time/9, pi_s4.vote_verification_time/9, pi_s5.vote_verification_time/9])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.02, legend_label='Pi_s', color='blue', marker='s', title='Vote verification stage')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.vote_verification_time/9, crypto_2.vote_verification_time/9, crypto_3.vote_verification_time/9, crypto_4.vote_verification_time/9, crypto_5.vote_verification_time/9])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.02, legend_label='Schoenmakers99', color='red', marker='s', title='Vote verification stage')
        h.show()

        k = Graphics()
        k += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.share_verification_time/9, pi_s2.share_verification_time/17, pi_s3.share_verification_time/33, pi_s4.share_verification_time/65, pi_s5.share_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=20, legend_label='Pi_s', color='blue', marker='s', title='Share verification stage')
        k += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.share_verification_time/9, crypto_2.share_verification_time/17, crypto_3.share_verification_time/33, crypto_4.share_verification_time/65, crypto_5.share_verification_time/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=20, legend_label='Schoenmakers99', color='red', marker='s', title='Share verification stage')
        k.show()

        l = Graphics()
        l += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.tally_reconstruction_time/(pi_s1.t+1), pi_s2.tally_reconstruction_time/(pi_s2.t+1), pi_s3.tally_reconstruction_time/(pi_s3.t+1), pi_s4.tally_reconstruction_time/(pi_s4.t+1), pi_s5.tally_reconstruction_time/(pi_s5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Pi_s', color='blue', marker='s', title='Vote tallying stage')
        l += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.tally_reconstruction_time/(crypto_1.t+1), crypto_2.tally_reconstruction_time/(crypto_2.t+1), crypto_3.tally_reconstruction_time/(crypto_3.t+1), crypto_4.tally_reconstruction_time/(crypto_4.t+1), crypto_5.tally_reconstruction_time/(crypto_5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Schoenmakers99', color='red', marker='s', title='Vote tallying stage')
        l.show()

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

        acns_1 = ACNSMetrics(9)
        acns_2 = ACNSMetrics(17)
        acns_3 = ACNSMetrics(33)
        acns_4 = ACNSMetrics(65)
        acns_5 = ACNSMetrics(81)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.total_time_dealer, pi_s2.total_time_dealer, pi_s3.total_time_dealer, pi_s4.total_time_dealer, pi_s5.total_time_dealer])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Pi_s stage', color='blue', marker='s', title='Sharing stage')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.total_time_dealer, crypto_2.total_time_dealer, crypto_3.total_time_dealer, crypto_4.total_time_dealer, crypto_5.total_time_dealer])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Schoenmakers99', color='red', marker='s', title='Sharing stage')
        g += list_plot(list(zip([9, 17, 33, 65, 81], [acns_1.total_time_dealer, acns_2.total_time_dealer, acns_3.total_time_dealer, acns_4.total_time_dealer, acns_5.total_time_dealer])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='ACNS', color='green', marker='s', title='Sharing stage')
        g.show()

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 81], [pi_s1.total_time_party_verification/9, pi_s2.total_time_party_verification/17, pi_s3.total_time_party_verification/33, pi_s4.total_time_party_verification/65, pi_s5.total_time_party_verification/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=2.1, legend_label='Pi_s', color='blue', marker='s', title='Verification stage')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [crypto_1.total_time_party_verification/9, crypto_2.total_time_party_verification/17, crypto_3.total_time_party_verification/33, crypto_4.total_time_party_verification/65, crypto_5.total_time_party_verification/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=2.1, legend_label='Schoenmakers99', color='red', marker='s', title='Verification stage')
        h += list_plot(list(zip([9, 17, 33, 65, 81], [acns_1.total_time_party_verification/9, acns_2.total_time_party_verification/17, acns_3.total_time_party_verification/33, acns_4.total_time_party_verification/65, acns_5.total_time_party_verification/81])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=2.1, legend_label='ACNS', color='green', marker='s', title='Verification stage')
        h.show()

        k = Graphics()
        k += list_plot(list(zip([pi_s1.t+1, pi_s2.t+1, pi_s3.t+1, pi_s4.t+1], [pi_s1.total_time_party_reconstruction/(pi_s1.t+1), pi_s2.total_time_party_reconstruction/(pi_s2.t+1), pi_s3.total_time_party_reconstruction/(pi_s3.t+1), pi_s4.total_time_party_reconstruction/(pi_s4.t+1), pi_s5.total_time_party_reconstruction/(pi_s5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Pi_s', color='blue', marker='s', title='Reconstruction stage')
        k += list_plot(list(zip([crypto_1.t+1, crypto_2.t+1, crypto_3.t+1, crypto_4.t+1, crypto_5.t+1], [crypto_1.total_time_party_reconstruction/(crypto_1.t+1), crypto_2.total_time_party_reconstruction/(crypto_2.t+1), crypto_3.total_time_party_reconstruction/(crypto_3.t+1), crypto_4.total_time_party_reconstruction/(crypto_4.t+1), crypto_5.total_time_party_reconstruction/(crypto_5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='Schoenmakers99', color='red', marker='s', title='Reconstruction stage')
        k += list_plot(list(zip([acns_1.t+1, acns_2.t+1, acns_3.t+1, acns_4.t+1, acns_5.t+1], [acns_1.total_time_party_reconstruction/(acns_1.t+1), acns_2.total_time_party_reconstruction/(acns_2.t+1), acns_3.total_time_party_reconstruction/(acns_3.t+1), acns_4.total_time_party_reconstruction/(acns_4.t+1), acns_5.total_time_party_reconstruction/(acns_5.t+1)])), plotjoined=True, xmin=0, xmax=81, ymin=0, ymax=0.6, legend_label='ACNS', color='green', marker='s', title='Reconstruction stage')
        k.show()


# ComparisonMetric.fixed_talliers_evoting_pvss_schemes()
# ComparisonMetric.fixed_voters_evoting_pvss_schemes()
ComparisonMetric.base_pvss_schemes() 