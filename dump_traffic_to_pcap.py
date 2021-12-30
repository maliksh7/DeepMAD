# Step 1: Import packages and set the working directory
import subprocess as sub
import os
# from rich import print
# 

file = 100

while(file > 2):
# while(True):
    file_name = 1

    print("\n[* ] - Dumping file{} as data{}.pcap\n".format(file_name, file_name))

    print("\n<--------------------File {}------------------------>\n".format(file_name))

    p = sub.Popen(('dumpcap', '-i', 'wlp0s20f3', '-a', 'filesize:10',
                   '-w', 'pcapF/data{}.pcap'.format(file_name)), stdout=sub.PIPE)
    v = 'pcapF/data{}.pcap'.format(file_name)
    # print(v)
    for row in iter(p.stdout.readline, b''):
        print(row.rstrip())   # process here

    # print(file_name,v,'------------------')
    print("\n[ DONE ] - Saved pcap file as data{}.pcap\n".format(file_name))
    
    
    os.system(
    'python3 pcap_to_csv.py')
    os.system(
        'python3 mergeCSV.py')
    os.system(
        'python3 norrm.py')
    # os.system('python3 csv_to_h5.py')
    os.system(
        'python3 model.py')

    file -= 1

print('exit')
