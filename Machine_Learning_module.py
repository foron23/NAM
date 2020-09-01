import numpy as np
from numpy import random
import joblib
import socket
import sys
import struct

print("Loading ML module...")
model= joblib.load('RF_Classifier.sav')
print("Loaded.")

#https://rico-schmidt.name/pymotw-3/struct/index.html
s = struct.Struct('I I I I I f f I f I f f I I I') #formato del sample es %d,%d,%d,%d,%d,%f,%f,%d,%f,%d,%f,%f,%d,%d,%d

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('localhost', 4545)
sock.bind(server_address)
print("Socket ready")
while True:
    data, address = sock.recvfrom(4096)
    #print(data)
    unpacked_data = s.unpack(data)
    #print(unpacked_data)
    mysample = np.array(unpacked_data)
    #numpy reordering in order to make processable for the model.
    mysample = np.ndarray(shape = (1,15) , buffer = mysample)
    #print(mysample)
    prediction = model.predict(mysample)

    if data:
        sent = sock.sendto(prediction, address)
        print('The prediction based on the data given is : ', prediction)
