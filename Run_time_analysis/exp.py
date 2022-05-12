from numpy.random import exponential
import numpy as np
import re

def get_enc_time(exp):
    f = open("enc_times_lwevss.txt", "r")
    txt = f.read()
    times = re.findall(r'\d+', txt)
    times = np.array([float(i) for i in times])
    print(f'Median time for lewvss is : {np.median(times)}')
    print(f'Median time with malicious parties for lewvss is : {np.median(times + exp)}')

def get_waiting_time(exp):
    f = open("waiting_time", "r")
    txt = f.read()
    times = txt.split(',')
    times = np.array([float(i) for i in times[:-1]])
    print(f'Median time for pvss is : {np.median(times)}')
    print(f'Median time with malicious parties for pvss is : {np.median(times + exp)}')

if __name__ == "__main__":
    np.random.seed(10)
    exp = exponential(51200, 512)
    get_waiting_time(exp)
    get_enc_time(exp)