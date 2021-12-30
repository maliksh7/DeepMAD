import os
from flowmeter import Flowmeter


path = 'pcapF/'


arr = os.listdir(path)
print("\n[* ] - Number of Files to convert  = ", len(arr), "\n")
# print(type(arr))


# for uniquely naming the csv files
for file in range(0, len(arr)):

    file_name = 1

    print("\n[ * ] - Converting data_{}.pcap to data{}.csv\n".format(
        file_name, file_name))

    cat_pcap = path + arr[file]

    print("\n>>>   Full path of data_{}.pcap: \n".format(file_name), cat_pcap)

    feature_gen = Flowmeter(offline=cat_pcap, outfunc=None,
                            outfile='csvs/out{}.csv'.format(file_name))
    feature_gen.run()

    print(
        "\n[ * ] - Converted data_{}.pcap to data_{}.csv\n".format(file_name, file_name))
 
    # use norm.py class to perform to apply preprocessing on data here and d
    #make code modular, use date time module to figure naming of 
    #mechanism to clear files so that they're not posessed againa nd again