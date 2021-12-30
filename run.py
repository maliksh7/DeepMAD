import os
from flowmeter import Flowmeter
import subprocess as sub
<<<<<<< HEAD
# from rich import print


os.system(
    'python3 dump_traffic_to_pcap.py')

os.system(
    'python3 pcap_to_csv.py')

os.system(
    'python3 mergeCSV.py')

os.system(
    'python3 norrm.py')

# os.system('csv_to_h5.py')

os.system(
    'python3 model.py')
=======
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
>>>>>>> 3200919fa9a10d8733a8f450a464634b07920462
