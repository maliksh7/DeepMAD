import os
from flowmeter import Flowmeter
import subprocess as sub
from rich import print


os.system(
    'python3 /home/bullbat/fyp-2/code/flowmeter/SplitCap/dump_traffic_to_pcap.py')

os.system(
    'python3 /home/bullbat/fyp-2/code/flowmeter/SplitCap/pcap_to_csv.py')

# os.system(
#     'python3 /home/bullbat/fyp-2/code/flowmeter/SplitCap/mergeCSV.py')

os.system(
    'python3 /home/bullbat/fyp-2/code/flowmeter/SplitCap/norrm.py')

os.system(
    'python3 /home/bullbat/fyp-2/code/flowmeter/SplitCap/model.py')
