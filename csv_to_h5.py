import pandas as pd
filename = 'preprocessed_csv/preprocessed_data.csv'
filename2 = 'prediction_data/f1.h5'

df = pd.read_csv(filename)
df.info()
df.to_hdf(filename2, 'data', mode='a', format='table')

