# Kerberos Protocol Demo

This repo features files written in Python3 that are used to simulate the Kerberos protocol.

## Project Setup

Clone the repo and run main.py. You can view all the files involved using your favorite text editor.

Only Python 3.7 and above is supported due to the nature of the datetime module used.

```
git clone https://github.com/jimenezh/Kerberos-Protocol-Demo.git
cd Kerberos-Protocol-Demo
python3 main.py
```

## File Description

* main.py
  * Main file that simulates the Kerberos protocol.
* user.py
  * Models the user and its functions used in the Kerberos protocol.
* kerberos.py
  * Models the trusted server and its functions used in the Kerberos protocol.
* http.py
  * Models the HTTP service and its functions used in the Kerberos protocol.
* encryption.py
  * Helper file that assists with encryption and decryption.
* KDC.py
  * Models the Key Distribution Center that the trusted server uses in the Kerberos protocol.

