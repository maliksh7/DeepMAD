from matplotlib import pyplot as plt
import keras
import pandas as pd
from keras.models import Model
from tensorflow.keras.optimizers import RMSprop
from sklearn.metrics import f1_score
import logging
import gzip
import numpy as np
from tensorflow.keras.layers import (
    BatchNormalization, Input, Dense, Flatten, Dropout, Reshape, Conv2D, MaxPooling2D, UpSampling2D, Conv2DTranspose
)
from keras.callbacks import ModelCheckpoint
from keras import backend as K
from keras.models import Model, Sequential
from tensorflow.keras.optimizers import Adadelta, RMSprop, SGD, Adam
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics
from sklearn.linear_model import LogisticRegression
import matplotlib
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.utils import to_categorical
from tensorflow import keras
from tensorflow.keras import layers
import tensorflow
from sklearn import model_selection
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# %matplotlib inline


# Imports
# from tensorflow.keras.datasets import mnist

# Configuration options
feature_vector_length = 55
num_classes = 4

# ---------------------------- DNN Model --------------------------- #

# Creating DNN model


def create_model():
    # Set the input shape

    input_shape = (feature_vector_length, )
    print('Feature Shape: {}'.format(input_shape))

    # Creat the model
    model = Sequential()
    model.add(Input(shape=(55)))

    model.add(Dense(28, activation='relu'))
    model.add(Dropout(0.2))

    model.add(Dense(14, activation='relu'))
    model.add(Dropout(0.2))

    model.add(Dense(7, activation='relu'))
    model.add(Dropout(0.2))

    model.add(Dense(num_classes, activation='softmax'))

    return model


# Loading Trained DNN model

def load_trained_model(weights_path):
    model = create_model()
    model.load_weights(weights_path)
    return model


if __name__ == "__main__":

    # Loading model weights .....

    filename = ('/home/bullbat/fyp-2/code/flowmeter/SplitCap/MNAD-DNN.h5')
    model = load_trained_model(filename)

    path = '/home/bullbat/fyp-2/code/flowmeter/SplitCap/hdf5/'

    arr = os.listdir(path)
    print("\n[* ] - Number of Files to pass through model  = ", len(arr), "\n")
    # print(type(arr))
    for file in range(0, len(arr)):
        file_name = file + 1

        print("\n[ * ] - Passing file {} through the model\n".format(
            file_name, file_name))

        cat_url = path + arr[file]

        print("\n>>>   Full path of file {}: \n".format(file_name), cat_url)
        valid_df = pd.read_hdf(cat_url)

        # del valid_df['Unnamed: 0']
        # valid_df.columns

        # valid_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        # # Dropping all the rows with nan values
        # valid_df.dropna(inplace=True)

        # le = LabelEncoder()
        # Y = valid_df['Label']
        # len(Y)
        X = valid_df.iloc[:, :-1]

        # Y_train = to_categorical(, num_classes)
        Y_test = to_categorical(Y, num_classes)

        check = model.predict(X, verbose=0)

        print(check)
        check = check.round()
        print(check)

        # Dumping Malicious packets in app.log file

        for packet in check:
            # print('hi')
            # print(len(i))
            if packet[1] == 1 or packet[2] == 1 or packet[3] == 1:
                logging.basicConfig(filename='app.log', filemode='w',
                                    format='%(name)s - %(levelname)s - %(message)s')
                # dump this error to log file concurrently
                logging.warning(
                    '[ -- Malicious Packet get logged to a file -- ]')
                # logging.warning(raise ValueError("node already exists"))

            else:
                # else all is good. means activity is benign
                print('[ -- Benign Packet -- ]')

        print(f1_score(Y_test, check, average='macro'), 'f1')
