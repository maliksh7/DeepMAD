# Step 1: Import packages and set the working directory
# Change “/csv” to your desired working directory.

import os
import glob
import pandas as pd
os.chdir("./csvs")

# def tsk(df):
    # os.chdir("/home/mak/mak/maths/MNAD/updated_flow/MNAD-repo/prediction_data")
    # merged_csv.to_hdf('//prediction_data/merged_data11.h5', 'data', mode='a', format='table')
# prediction_data

    


# Step 2: Use glob to match the pattern ‘csv’
# Match the pattern (‘csv’) and save the list of file names in the ‘all_filenames’ variable.
# You can check out this link to learn more about regular expression matching.

extension = 'csv'
all_filenames = [i for i in glob.glob('*.{}'.format(extension))]
print("\n---->    Collected csv files to merge = {}\n".format(len(all_filenames)))

# /home/mak/mak/maths/MNAD/updated_flow/MNAD-repo/csvs
# /home/mak/mak/maths/MNAD/updated_flow/MNAD-repo/prediction_data
# /home/mak/mak/maths/MNAD/updated_flow/MNAD-repo/mergeCSV.py


# Step 3: Combine all files in the list and export as CSV
# Use pandas to concatenate all files in the list and export as CSV.
# The output file is named “merged_csv.csv” located in your working directory.

# combine all files in the list
merged_csv = pd.concat([pd.read_csv(f) for f in all_filenames])

# os.chdir("prediction_data")

# filename = 'csvs/merged_data.csv'
# export to csv
print("\n[ * ] - Merging cvs files as merged_data.csv\n")
merged_csv.to_csv('merged_data.csv', index=False, encoding='utf-8-sig')
# tsk(merged_csv)
# merged_csv.to_hdf('/prediction_data/merged_data11.h5', 'data', mode='w', format='table')


print("\n[ * ] - Merged {} csv files !!!\n".format(len(all_filenames)))
