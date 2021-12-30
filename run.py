import os
from flowmeter import Flowmeter
import subprocess as sub
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
