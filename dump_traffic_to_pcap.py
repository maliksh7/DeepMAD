# Step 1: Import packages and set the working directory
import subprocess as sub
from rich import print


file = 0

while(file < 2):

    file_name = file + 1

    print("\n[* ] - Dumping file{} as data{}.pcap\n".format(file_name, file_name))

    print("\n<--------------------File {}------------------------>\n".format(file_name))

    p = sub.Popen(('dumpcap', '-i', 'wlp1s0', '-a', 'filesize:600',
                   '-w', 'pcapF/data{}.pcap'.format(file_name)), stdout=sub.PIPE)
    for row in iter(p.stdout.readline, b''):
        print(row.rstrip())   # process here

    print("\n[ DONE ] - Saved pcap file as data{}.pcap\n".format(file_name))

    file += 1
