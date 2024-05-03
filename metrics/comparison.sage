import os

os.system('sage --preparse pi_s.sage')
os.system('mv pi_s.sage.py pi_s.py')

from pi_s import *


class ComparisonMetric:
    def __init__(self):
        pi_s9 = Pi_s_Metrics(9)
        print("9 parties done")
        pi_s33 = Pi_s_Metrics(33)
        print("33 parties done")
        pi_s65 = Pi_s_Metrics(65)
        print("65 parties done")
        pi_s101 = Pi_s_Metrics(101)
        print("101 parties done")

        f = open("comparison_data.txt", "w")
        f.write("sharing stage: " + str(list(zip([pi_s9.total_time_dealer, pi_s33.total_time_dealer, pi_s65.total_time_dealer, pi_s101.total_time_dealer], [9, 33, 65, 101]))) + "\r\n")
        f.write("verification stage: " + str(list(zip([pi_s9.total_time_party_verification/9, pi_s33.total_time_party_verification/33, pi_s65.total_time_party_verification/65, pi_s101.total_time_party_verification/101], [9, 33, 65, 101])))+ "\r\n")
        f.write("reconstruction stage: " + str(list(zip([pi_s9.total_time_party_reconstruction/(pi_s9.t+1), pi_s33.total_time_party_reconstruction/(pi_s33.t+1), pi_s65.total_time_party_reconstruction/(pi_s65.t+1), pi_s101.total_time_party_reconstruction/(pi_s101.t+1)], [pi_s9.t+1, pi_s33.t+1, pi_s65.t+1, pi_s101.t+1])))+ "\r\n")

        #list_plot(list(zip([pi_s9.total_time_dealer, pi_s33.total_time_dealer, pi_s65.total_time_dealer, pi_s101.total_time_dealer], [9, 33, 65, 101])), plotJoined=True) 
        #! Plotting only works when entered directly on the command line

    
plot = ComparisonMetric()