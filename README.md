<<<<<<< HEAD
This code is adapted from [torusresearch/pvss](https://github.com/torusresearch/pvss)


=======
This code is adapted from [torusresearch/pvss](https://github.com/torusresearch/pvss), and [shaih/cpp-lwevss](https://github.com/shaih/cpp-lwevss).

To reproduce the results in Table 1 and Table 2 in our report, please run the following:

```
cd Run_time_analysis
python exp.py
```
>>>>>>> 

To run the C++ code on LWE PVSS:
```
cd cpp-lwe-pvss
cmake .
make
./lwe-pvss-main [argument]

```
The argument is the number of parties that will take part in the protocol.

>>>>>>> 

To run the Python code on VRF based leader selection:

```
cd Verifiable-Random-Functions
python eval_VRF.py [argument]

```
The argument can be any integer that will be used as a nonce in the initial evaluation.