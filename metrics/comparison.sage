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
        pi_s5 = Pi_sEvotingMetrics(129, 9)

        crypto_1 = Crypto99EvotingMetrics(9, 9)
        crypto_2 = Crypto99EvotingMetrics(17, 9)
        crypto_3 = Crypto99EvotingMetrics(33, 9)
        crypto_4 = Crypto99EvotingMetrics(65, 9)
        crypto_5 = Crypto99EvotingMetrics(129, 9)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65, 129], [pi_s1.casting_time, pi_s2.casting_time, pi_s3.casting_time, pi_s4.casting_time, pi_s5.casting_time])), plotjoined=True, legend_label='[Bag23]', color='blue', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65, 129], [crypto_1.casting_time, crypto_2.casting_time, crypto_3.casting_time, crypto_4.casting_time, crypto_5.casting_time])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=7, legend_label='[Sch99]', color='red', marker='s')
        g.show(gridlines="minor", axes_labels=['Number of voters', 'Time (s)'])

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 129], [pi_s1.vote_verification_time/9, pi_s2.vote_verification_time/17, pi_s3.vote_verification_time/33, pi_s4.vote_verification_time/65, pi_s5.vote_verification_time/129])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.02, legend_label='[Bag23]', color='blue', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65, 129], [crypto_1.vote_verification_time/9, crypto_2.vote_verification_time/17, crypto_3.vote_verification_time/33, crypto_4.vote_verification_time/65, crypto_5.vote_verification_time/129])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.02, legend_label='[Sch99]', color='red', marker='s')
        h.show(gridlines="minor", axes_labels=['Number of voters', 'Time (s)'])

        k = Graphics()
        k += list_plot(list(zip([9, 17, 33, 65, 129], [pi_s1.share_verification_time/9, pi_s2.share_verification_time/9, pi_s3.share_verification_time/9, pi_s4.share_verification_time/9, pi_s5.share_verification_time/9])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=6, legend_label='[Bag23]', color='blue', marker='s')
        k += list_plot(list(zip([9, 17, 33, 65, 129], [crypto_1.share_verification_time/9, crypto_2.share_verification_time/9, crypto_3.share_verification_time/9, crypto_4.share_verification_time/9, crypto_5.share_verification_time/9])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=6, legend_label='[Sch99]', color='red', marker='s')
        k.show(gridlines="minor", axes_labels=['Number of voters', 'Time (s)'])

        l = Graphics()
        l += list_plot(list(zip([9, 17, 33, 65, 129], [pi_s1.tally_reconstruction_time/(pi_s1.t+1), pi_s2.tally_reconstruction_time/(pi_s2.t+1), pi_s3.tally_reconstruction_time/(pi_s3.t+1), pi_s4.tally_reconstruction_time/(pi_s4.t+1), pi_s5.tally_reconstruction_time/(pi_s5.t+1)])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.1, legend_label='[Bag23]', color='blue', marker='s')
        l += list_plot(list(zip([9, 17, 33, 65, 129], [crypto_1.tally_reconstruction_time/(crypto_1.t+1), crypto_2.tally_reconstruction_time/(crypto_2.t+1), crypto_3.tally_reconstruction_time/(crypto_3.t+1), crypto_4.tally_reconstruction_time/(crypto_4.t+1), crypto_5.tally_reconstruction_time/(crypto_5.t+1)])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.1, legend_label='[Sch99]', color='red', marker='s')
        l.show(gridlines="minor", axes_labels=['Number of voters', 'Time (s)'])

        f = open("fixed_talliers_evoting.txt", "w")
        f.write("-------PI_S---------\n")
        f.write("& " + str(pi_s1.n) + " & " + str(pi_s2.n) + " & " + str(pi_s3.n) + " & " + str(pi_s4.n) + " & " + str(pi_s5.n) + " \\\\ \n")
        f.write("Ballot casting time & " + str(pi_s1.casting_time) + " & " + str(pi_s2.casting_time) + " & " + str(pi_s3.casting_time) + " & " + str(pi_s4.casting_time) + " & " + str(pi_s5.casting_time) + " \\\\ \n")
        f.write("Vote verification time & " + str(pi_s1.vote_verification_time/9) + " & " + str(pi_s2.vote_verification_time/17) + " & " + str(pi_s3.vote_verification_time/33) + " & " + str(pi_s4.vote_verification_time/65) + " & " + str(pi_s5.vote_verification_time/129) + " \\\\ \n")
        f.write("Share verification time & " + str(pi_s1.share_verification_time/9) + " & " + str(pi_s2.share_verification_time/9) + " & " + str(pi_s3.share_verification_time/9) + " & " + str(pi_s4.share_verification_time/9) + " & " + str(pi_s5.share_verification_time/9) + " \\\\ \n")
        f.write("Vote tallying time & " + str(pi_s1.tally_reconstruction_time/(pi_s1.t+1)) + " & " + str(pi_s2.tally_reconstruction_time/(pi_s2.t+1)) + " & " + str(pi_s3.tally_reconstruction_time/(pi_s3.t+1)) + " & " + str(pi_s4.tally_reconstruction_time/(pi_s4.t+1)) + " & " + str(pi_s5.tally_reconstruction_time/(pi_s5.t+1)) + " \\\\ \n")
        f.write("-------CRYPTO99---------\n")
        f.write("& " + str(crypto_1.n) + " & " + str(crypto_2.n) + " & " + str(crypto_3.n) + " & " + str(crypto_4.n) + " & " + str(crypto_5.n) + " \\\\ \n")
        f.write("Ballot casting time & " + str(crypto_1.casting_time) + " & " + str(crypto_2.casting_time) + " & " + str(crypto_3.casting_time) + " & " + str(crypto_4.casting_time) + " & " + str(crypto_5.casting_time) + " \\\\ \n")
        f.write("Vote verification time & " + str(crypto_1.vote_verification_time/9) + " & " + str(crypto_2.vote_verification_time/17) + " & " + str(crypto_3.vote_verification_time/33) + " & " + str(crypto_4.vote_verification_time/65) + " & " + str(crypto_5.vote_verification_time/129) + " \\\\ \n")
        f.write("Share verification time & " + str(crypto_1.share_verification_time/9) + " & " + str(crypto_2.share_verification_time/9) + " & " + str(crypto_3.share_verification_time/9) + " & " + str(crypto_4.share_verification_time/9) + " & " + str(crypto_5.share_verification_time/9) + " \\\\ \n")
        f.write("Vote tallying time & " + str(crypto_1.tally_reconstruction_time/(crypto_1.t+1)) + " & " + str(crypto_2.tally_reconstruction_time/(crypto_2.t+1)) + " & " + str(crypto_3.tally_reconstruction_time/(crypto_3.t+1)) + " & " + str(crypto_4.tally_reconstruction_time/(crypto_4.t+1)) + " & " + str(crypto_5.tally_reconstruction_time/(crypto_5.t+1)) + " \\\\ \n")

    def fixed_voters_evoting_pvss_schemes():
        pi_s1 = Pi_sEvotingMetrics(9, 9)
        pi_s2 = Pi_sEvotingMetrics(9, 17)
        pi_s3 = Pi_sEvotingMetrics(9, 33)
        pi_s4 = Pi_sEvotingMetrics(9, 65)

        crypto_1 = Crypto99EvotingMetrics(9, 9)
        crypto_2 = Crypto99EvotingMetrics(9, 17)
        crypto_3 = Crypto99EvotingMetrics(9, 33)
        crypto_4 = Crypto99EvotingMetrics(9, 65)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65], [pi_s1.casting_time, pi_s2.casting_time, pi_s3.casting_time, pi_s4.casting_time])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=5, legend_label='[Bag23]', color='blue', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65], [crypto_1.casting_time, crypto_2.casting_time, crypto_3.casting_time, crypto_4.casting_time])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=5, legend_label='[Sch99]', color='red', marker='s')
        g.show(gridlines="minor", axes_labels=['Number of talliers', 'Time (s)'])

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65], [pi_s1.vote_verification_time/9, pi_s2.vote_verification_time/9, pi_s3.vote_verification_time/9, pi_s4.vote_verification_time/9])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.02, legend_label='[Bag23]', color='blue', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65], [crypto_1.vote_verification_time/9, crypto_2.vote_verification_time/9, crypto_3.vote_verification_time/9, crypto_4.vote_verification_time/9])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.02, legend_label='[Sch99]', color='red', marker='s')
        h.show(gridlines="minor", axes_labels=['Number of talliers', 'Time (s)'])

        k = Graphics()
        k += list_plot(list(zip([9, 17, 33, 65], [pi_s1.share_verification_time/9, pi_s2.share_verification_time/17, pi_s3.share_verification_time/33, pi_s4.share_verification_time/65])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=20, legend_label='[Bag23]', color='blue', marker='s')
        k += list_plot(list(zip([9, 17, 33, 65], [crypto_1.share_verification_time/9, crypto_2.share_verification_time/17, crypto_3.share_verification_time/33, crypto_4.share_verification_time/65])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=20, legend_label='[Sch99]', color='red', marker='s')
        k.show(gridlines="minor", axes_labels=['Number of talliers', 'Time (s)'])

        l = Graphics()
        l += list_plot(list(zip([9, 17, 33, 65], [pi_s1.tally_reconstruction_time/(pi_s1.t+1), pi_s2.tally_reconstruction_time/(pi_s2.t+1), pi_s3.tally_reconstruction_time/(pi_s3.t+1), pi_s4.tally_reconstruction_time/(pi_s4.t+1)])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.6, legend_label='[Bag23]', color='blue', marker='s')
        l += list_plot(list(zip([9, 17, 33, 65], [crypto_1.tally_reconstruction_time/(crypto_1.t+1), crypto_2.tally_reconstruction_time/(crypto_2.t+1), crypto_3.tally_reconstruction_time/(crypto_3.t+1), crypto_4.tally_reconstruction_time/(crypto_4.t+1)])), plotjoined=True, xmin=0, xmax=129, ymin=0, ymax=0.6, legend_label='[Sch99]', color='red', marker='s')
        l.show(gridlines="minor", axes_labels=['Number of talliers', 'Time (s)'])

        f = open("fixed_voters_evoting.txt", "w")
        f.write("-------PI_S---------\n")
        f.write("& " + str(pi_s1.m) + " & " + str(pi_s2.m) + " & " + str(pi_s3.m) + " & " + str(pi_s4.m) + " & " + " \\\\ \n")
        f.write("Ballot casting time & " + str(pi_s1.casting_time) + " & " + str(pi_s2.casting_time) + " & " + str(pi_s3.casting_time) + " & " + str(pi_s4.casting_time) + " & " + " \\\\ \n")
        f.write("Vote verification time & " + str(pi_s1.vote_verification_time/9) + " & " + str(pi_s2.vote_verification_time/17) + " & " + str(pi_s3.vote_verification_time/33) + " & " + str(pi_s4.vote_verification_time/65) + " & " + " \\\\ \n")
        f.write("Share verification time & " + str(pi_s1.share_verification_time/9) + " & " + str(pi_s2.share_verification_time/9) + " & " + str(pi_s3.share_verification_time/9) + " & " + str(pi_s4.share_verification_time/9) + " & " + " \\\\ \n")
        f.write("Vote tallying time & " + str(pi_s1.tally_reconstruction_time/(pi_s1.t+1)) + " & " + str(pi_s2.tally_reconstruction_time/(pi_s2.t+1)) + " & " + str(pi_s3.tally_reconstruction_time/(pi_s3.t+1)) + " & " + str(pi_s4.tally_reconstruction_time/(pi_s4.t+1)) + " & " + " \\\\ \n")
        f.write("-------CRYPTO99---------\n")
        f.write("& " + str(crypto_1.n) + " & " + str(crypto_2.n) + " & " + str(crypto_3.n) + " & " + str(crypto_4.n) + " & " + " \\\\ \n")
        f.write("Ballot casting time & " + str(crypto_1.casting_time) + " & " + str(crypto_2.casting_time) + " & " + str(crypto_3.casting_time) + " & " + str(crypto_4.casting_time) + " & " + " \\\\ \n")
        f.write("Vote verification time & " + str(crypto_1.vote_verification_time/9) + " & " + str(crypto_2.vote_verification_time/17) + " & " + str(crypto_3.vote_verification_time/33) + " & " + str(crypto_4.vote_verification_time/65) + " & " + " \\\\ \n")
        f.write("Share verification time & " + str(crypto_1.share_verification_time/9) + " & " + str(crypto_2.share_verification_time/9) + " & " + str(crypto_3.share_verification_time/9) + " & " + str(crypto_4.share_verification_time/9) + " & " + " \\\\ \n")
        f.write("Vote tallying time & " + str(crypto_1.tally_reconstruction_time/(crypto_1.t+1)) + " & " + str(crypto_2.tally_reconstruction_time/(crypto_2.t+1)) + " & " + str(crypto_3.tally_reconstruction_time/(crypto_3.t+1)) + " & " + str(crypto_4.tally_reconstruction_time/(crypto_4.t+1)) + " & " + " \\\\ \n")

    def base_pvss_schemes():
        # Take powers of 2 values
        pi_s1 = Pi_s_Metrics(9)
        pi_s2 = Pi_s_Metrics(17)
        pi_s3 = Pi_s_Metrics(33)
        pi_s4 = Pi_s_Metrics(65)
        pi_s5 = Pi_s_Metrics(129)

        crypto_1 = Crypto99Metrics(9)
        crypto_2 = Crypto99Metrics(17)
        crypto_3 = Crypto99Metrics(33)
        crypto_4 = Crypto99Metrics(65)
        crypto_5 = Crypto99Metrics(129)

        acns_1 = ACNSMetrics(9)
        acns_2 = ACNSMetrics(17)
        acns_3 = ACNSMetrics(33)
        acns_4 = ACNSMetrics(65)
        acns_5 = ACNSMetrics(129)

        g = Graphics()
        g += list_plot(list(zip([9, 17, 33, 65, 129], [pi_s1.total_time_dealer, pi_s2.total_time_dealer, pi_s3.total_time_dealer, pi_s4.total_time_dealer, pi_s5.total_time_dealer])), plotjoined=True, legend_label='[Bag23]', color='blue', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65, 129], [crypto_1.total_time_dealer, crypto_2.total_time_dealer, crypto_3.total_time_dealer, crypto_4.total_time_dealer, crypto_5.total_time_dealer])), plotjoined=True, legend_label='[Sch99]', color='red', marker='s')
        g += list_plot(list(zip([9, 17, 33, 65, 129], [acns_1.total_time_dealer, acns_2.total_time_dealer, acns_3.total_time_dealer, acns_4.total_time_dealer, acns_5.total_time_dealer])), plotjoined=True, legend_label='[CD17]', color='green', marker='s')
        g.show(gridlines="minor", axes_labels=['Number of parties', 'Time (s)'])

        h = Graphics()
        h += list_plot(list(zip([9, 17, 33, 65, 129], [pi_s1.total_time_party_verification/9, pi_s2.total_time_party_verification/17, pi_s3.total_time_party_verification/33, pi_s4.total_time_party_verification/65, pi_s5.total_time_party_verification/129])), plotjoined=True, legend_label='[Bag23]', color='blue', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65, 129], [crypto_1.total_time_party_verification/9, crypto_2.total_time_party_verification/17, crypto_3.total_time_party_verification/33, crypto_4.total_time_party_verification/65, crypto_5.total_time_party_verification/129])), plotjoined=True, legend_label='[Sch99]', color='red', marker='s')
        h += list_plot(list(zip([9, 17, 33, 65, 129], [acns_1.total_time_party_verification/9, acns_2.total_time_party_verification/17, acns_3.total_time_party_verification/33, acns_4.total_time_party_verification/65, acns_5.total_time_party_verification/129])), plotjoined=True, legend_label='[CD17]', color='green', marker='s')
        h.show(gridlines="minor", axes_labels=['Number of parties', 'Time (s)'])

        k = Graphics()
        k += list_plot(list(zip([pi_s1.t+1, pi_s2.t+1, pi_s3.t+1, pi_s4.t+1], [pi_s1.total_time_party_reconstruction/(pi_s1.t+1), pi_s2.total_time_party_reconstruction/(pi_s2.t+1), pi_s3.total_time_party_reconstruction/(pi_s3.t+1), pi_s4.total_time_party_reconstruction/(pi_s4.t+1), pi_s5.total_time_party_reconstruction/(pi_s5.t+1)])), plotjoined=True, legend_label='[Bag23]', color='blue', marker='s')
        k += list_plot(list(zip([crypto_1.t+1, crypto_2.t+1, crypto_3.t+1, crypto_4.t+1, crypto_5.t+1], [crypto_1.total_time_party_reconstruction/(crypto_1.t+1), crypto_2.total_time_party_reconstruction/(crypto_2.t+1), crypto_3.total_time_party_reconstruction/(crypto_3.t+1), crypto_4.total_time_party_reconstruction/(crypto_4.t+1), crypto_5.total_time_party_reconstruction/(crypto_5.t+1)])), plotjoined=True, legend_label='[Sch99]', color='red', marker='s')
        k += list_plot(list(zip([acns_1.t+1, acns_2.t+1, acns_3.t+1, acns_4.t+1, acns_5.t+1], [acns_1.total_time_party_reconstruction/(acns_1.t+1), acns_2.total_time_party_reconstruction/(acns_2.t+1), acns_3.total_time_party_reconstruction/(acns_3.t+1), acns_4.total_time_party_reconstruction/(acns_4.t+1), acns_5.total_time_party_reconstruction/(acns_5.t+1)])), plotjoined=True, legend_label='[CD17]', color='green', marker='s')
        k.show(gridlines="minor", axes_labels=['Number of parties', 'Time (s)'])

        f = open("base_pvss_schemes.txt", "w")
        f.write("-------PI_S---------\n")
        f.write("& " + str(pi_s1.n) + " & " + str(pi_s2.n) + " & " + str(pi_s3.n) + " & " + str(pi_s4.n) + " & " + str(pi_s5.n) + " \\\\ \n")
        f.write("Dealer time & " + str(pi_s1.total_time_dealer) + " & " + str(pi_s2.total_time_dealer) + " & " + str(pi_s3.total_time_dealer) + " & " + str(pi_s4.total_time_dealer) + " & " + str(pi_s5.total_time_dealer) + " \\\\ \n")
        f.write("Party verification time & " + str(pi_s1.total_time_party_verification/9) + " & " + str(pi_s2.total_time_party_verification/17) + " & " + str(pi_s3.total_time_party_verification/33) + " & " + str(pi_s4.total_time_party_verification/65) + " & " + str(pi_s5.total_time_party_verification/129) + " \\\\ \n")
        f.write("Party reconstruction time & " + str(pi_s1.total_time_party_reconstruction/(pi_s1.t+1)) + " & " + str(pi_s2.total_time_party_reconstruction/(pi_s2.t+1)) + " & " + str(pi_s3.total_time_party_reconstruction/(pi_s3.t+1)) + " & " + str(pi_s4.total_time_party_reconstruction/(pi_s4.t+1)) + " & " + str(pi_s5.total_time_party_reconstruction/(pi_s5.t+1)) + " \\\\ \n")
        f.write("-------CRYPTO99---------\n")
        f.write("& " + str(crypto_1.n) + " & " + str(crypto_2.n) + " & " + str(crypto_3.n) + " & " + str(crypto_4.n) + " & " + str(crypto_5.n) + " \\\\ \n")
        f.write("Dealer time & " + str(crypto_1.total_time_dealer) + " & " + str(crypto_2.total_time_dealer) + " & " + str(crypto_3.total_time_dealer) + " & " + str(crypto_4.total_time_dealer) + " & " + str(crypto_5.total_time_dealer) + " \\\\ \n")
        f.write("Party verification time & " + str(crypto_1.total_time_party_verification/9) + " & " + str(crypto_2.total_time_party_verification/17) + " & " + str(crypto_3.total_time_party_verification/33) + " & " + str(crypto_4.total_time_party_verification/65) + " & " + str(crypto_5.total_time_party_verification/129) + " \\\\ \n")
        f.write("Party reconstruction time & " + str(crypto_1.total_time_party_reconstruction/(crypto_1.t+1)) + " & " + str(crypto_2.total_time_party_reconstruction/(crypto_2.t+1)) + " & " + str(crypto_3.total_time_party_reconstruction/(crypto_3.t+1)) + " & " + str(crypto_4.total_time_party_reconstruction/(crypto_4.t+1)) + " & " + str(crypto_5.total_time_party_reconstruction/(crypto_5.t+1)) + " \\\\ \n")
        f.write("-------ACNS---------\n")
        f.write("& " + str(acns_1.n) + " & " + str(acns_2.n) + " & " + str(acns_3.n) + " & " + str(acns_4.n) + " & " + str(acns_5.n) + " \\\\ \n")
        f.write("Dealer time & " + str(acns_1.total_time_dealer) + " & " + str(acns_2.total_time_dealer) + " & " + str(acns_3.total_time_dealer) + " & " + str(acns_4.total_time_dealer) + " & " + str(acns_5.total_time_dealer) + " \\\\ \n")
        f.write("Party verification time & " + str(acns_1.total_time_party_verification/9) + " & " + str(acns_2.total_time_party_verification/17) + " & " + str(acns_3.total_time_party_verification/33) + " & " + str(acns_4.total_time_party_verification/65) + " & " + str(acns_5.total_time_party_verification/129) + " \\\\ \n")
        f.write("Party reconstruction time & " + str(acns_1.total_time_party_reconstruction/(acns_1.t+1)) + " & " + str(acns_2.total_time_party_reconstruction/(acns_2.t+1)) + " & " + str(acns_3.total_time_party_reconstruction/(acns_3.t+1)) + " & " + str(acns_4.total_time_party_reconstruction/(acns_4.t+1)) + " & " + str(acns_5.total_time_party_reconstruction/(acns_5.t+1)) + " \\\\ \n")


# ComparisonMetric.fixed_talliers_evoting_pvss_schemes()
# ComparisonMetric.fixed_voters_evoting_pvss_schemes()
ComparisonMetric.base_pvss_schemes() 