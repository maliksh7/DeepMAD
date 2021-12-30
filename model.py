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


''' 
        Change the dataframe column names names so that new data can be passed thru model at runtime.

'''


# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# %matplotlib inline

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


def ready_tyaar(valid_df):
    valid_df.info()
    if valid_df[' Label']:
        if valid_df['Unnamed: 0']:
            del valid_df['Unnamed: 0']
            del valid_df[' Label']
        # return valid_df

    else:
        # del valid_df['Unnamed: 0']
        return valid_df


def pass_model(data):
    print('this is frame')
    print(type(data))
    check = model.predict(data, verbose=0)
    check = check.round()
    return check


# def pass_model(data):
#     check = model.predict(data, verbose=0)
#     check = check.round()
#     return check


def check_label(check):
    # file = open(“testfile.txt”, ”w”)
    for packet in check:

        if packet[1] == 1 or packet[2] == 1 or packet[3] == 1:
            print('[ -- Malicious Packet -- ]')
            f = open("check.txt", "a")
            f.write("This File has Malicious Activity!")
            f.close()

    else:
        # else all is good. means activity is benign
        print('[ -- Benign Packet -- ]')
        f = open("check.txt", "a")
        f.write("This File has Benign Activity")
        f.close()


def iocheckk(model):
    model.summary()
    # print(i.shape, i.dtype) for i in model.inputs
    # print(o.shape, o.dtype) for o in model.outputs
    # print(l.name, l.input_shape, l.dtype) for l in model.layers


if __name__ == "__main__":

    filename = ('MNAD-DNN.h5')
    model = load_trained_model(filename)
    print(model.weights[0])

    path = 'prediction_data/'

    arr = os.listdir(path)
    print("\n[* ] - Number of Files to pass through model  = ", len(arr), "\n")

    # print(iocheckk(model))

    for file in range(0, len(arr)):
        file_name = file + 1

        print("\n[ * ] - Passing file {} through the model\n".format(
            file_name))

        cat_url = path + arr[file]

        print("\n>>>   Full path of file {}: \n".format(file_name), cat_url)
        valid_df = pd.read_hdf(cat_url)
        # if valid_df['Unnamed: 0']:
            # del valid_df['Unnamed: 0']
        valid_df.info()
        # valid_df = ready_tyaar(valid_df)
        print(type(valid_df), '???')

        check = pass_model(valid_df)
        print('checking label')
        check_label(check)
