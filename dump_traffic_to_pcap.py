# Step 1: Import packages and set the working directory
import subprocess as sub
import os
from flowmeter import Flowmeter
from rich import print
from rich.theme import Theme
from rich.console import Console

# dict of rich colors
# color used in project
ct = Theme({
    'good': "bold green ",
    'bad': "red",
    'blue': "blue",
    'yellow': "yellow",
    'purple': "purple",
    'magenta': "magenta",
    'cyan': "cyan"
})
rc = Console(record=True, theme=ct)


# Step2: Include files for logo, dashboard and task manager

os.system(
    'python3 rich/logo.py')

os.system(
    'python3 rich/task-analyzer.py')

os.system(
    'python3 rich/cli_dashboard.py')

# os.system(
#     'python3 rich/logo.py')

# Step 3: Capture network traffic and dump in to a *.pcap file formate

file = 0

# while(file <= 5):
while True:
    file_name = file + 1

    rc.log(
        "\n[cyan][* ] - Dumping file{} as data{}.pcap[/]\n".format(file_name, file_name))

    rc.log(
        "\n[blue]<--------------------File {}------------------------>[/]\n".format(file_name))

    p = sub.Popen(('dumpcap', '-i', 'wlp1s0', '-a', 'filesize:10',
                   '-w', 'pcapF/data{}.pcap'.format(file_name)), stdout=sub.PIPE)

    for row in iter(p.stdout.readline, b''):
        rc.log(row.rstrip())   # process here

    rc.log(
        "\n[good][ DONE ][/][cyan] - Saved pcap file as data{}.pcap[/]\n".format(file_name))

    # Convert the *.pcap to *.csv file
    # os.system(
    #     'python3 pcap_to_csv.py')
    path = 'pcapF/'

    arr = os.listdir(path)
    cat_pcap = path + arr[file]
    feature_gen = Flowmeter(offline=cat_pcap, outfunc=None,
                            outfile='csvs/out{}.csv'.format(file_name))
    feature_gen.run()

    # Normalize and preprocessing of *.csv file to fed the ML/ DL models.
    os.system(
        'python3 norrm.py')

    # classify the activity from model
    os.system(
        'python3 model.py')

    file += 1

rc.save_html("report.html")
rc.log('exit')
