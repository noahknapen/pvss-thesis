import os

os.system('sage --preparse pi_s.sage')
os.system('mv pi_s.sage.py pi_s.py')

os.system('sage --preparse crypto99.sage')
os.system('mv crypto99.sage.py crypto99.py')

from pi_s import *
from crypto99 import *


class ComparisonMetric:
    def __init__(self):
        pi_s1 = Pi_s_Metrics(9)
        pi_s2 = Pi_s_Metrics(33)
        pi_s3 = Pi_s_Metrics(65)
        pi_s4 = Pi_s_Metrics(101)

        crypto_1 = Crypto99Metrics(9)
        crypto_2 = Crypto99Metrics(33)
        crypto_3 = Crypto99Metrics(65)
        crypto_4 = Crypto99Metrics(101)

        f = open("comparison_data.txt", "w")
        f.write("---------------------------Pi_s PVSS---------------------------\r\n")
        f.write("sharing stage: " + str(list(zip([9, 33, 65, 101], [pi_s1.total_time_dealer, pi_s2.total_time_dealer, pi_s3.total_time_dealer, pi_s4.total_time_dealer]))) + "\r\n")
        f.write("verification stage: " + str(list(zip([9, 33, 65, 101], [pi_s1.total_time_party_verification/9, pi_s2.total_time_party_verification/33, pi_s3.total_time_party_verification/65, pi_s4.total_time_party_verification/101])))+ "\r\n")
        f.write("reconstruction stage: " + str(list(zip([pi_s1.t+1, pi_s2.t+1, pi_s3.t+1, pi_s4.t+1], [pi_s1.total_time_party_reconstruction/(pi_s1.t+1), pi_s2.total_time_party_reconstruction/(pi_s2.t+1), pi_s3.total_time_party_reconstruction/(pi_s3.t+1), pi_s4.total_time_party_reconstruction/(pi_s4.t+1)])))+ "\r\n")
        f.write("---------------------------Crypto99 PVSS-----------------------\r\n")
        f.write("sharing stage: " + str(list(zip([9, 33, 65, 101], [crypto_1.total_time_dealer, crypto_2.total_time_dealer, crypto_3.total_time_dealer, crypto_4.total_time_dealer])))+ "\r\n")
        f.write("verification stage: " + str(list(zip([9, 33, 65, 101], [crypto_1.total_time_party_verification/9, crypto_2.total_time_party_verification/33, crypto_3.total_time_party_verification/65, crypto_4.total_time_party_verification/101])))+ "\r\n")
        f.write("reconstruction stage: " + str(list(zip([crypto_1.t+1, crypto_2.t+1, crypto_3.t+1, crypto_4.t+1], [crypto_1.total_time_party_reconstruction/(crypto_1.t+1), crypto_2.total_time_party_reconstruction/(crypto_2.t+1), crypto_3.total_time_party_reconstruction/(crypto_3.t+1), crypto_4.total_time_party_reconstruction/(crypto_4.t+1)])))+ "\r\n")

        # g = Graphics()
        # g += list_plot(..., plotjoined=True, xmin=0, xmax=101, ymin=0, ymax=1, legend_label='Sharing stage', color='blue')
        # g += list_plot(..., plotjoined=True, xmin=0, xmax=101, ymin=0, ymax=1, legend_label='Verification stage', color='red')
        # g += list_plot(..., plotjoined=True, xmin=0, xmax=101, ymin=0, ymax=1, legend_label='Reconstruction stage', color='black')
        # g.show()

    
plot = ComparisonMetric()