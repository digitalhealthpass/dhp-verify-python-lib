## Readme Packaging

**<sup>®</sup> Digital Health Pass**

# Multi-Credential Verifier Library (Python) Source Code Encryption and Packaging

**March 2022** 

Note: This README is for internal use only and should not be distributed

## Encrypting and Packaging Source Code for Distribution to Customers

The SDK source code must be encrypted using Pyarmor and packaged into a wheel file for customer distribution.  Ensure Pyarmor 6.8.1 is installed and licensed before beginning.

From the command line follow these steps

- From the project root directory run `python3 setup.py bdist_wheel` which will create a `.whl` file in the `dist` folder

- Navigate to the `dist` folder and run `unzip multi_cred_verifier_python-0.1.0-py3-none-any.whl`

- Delete multi_cred_verifier_python-0.1.0-py3-none-any.whl

- Run `pyarmor obfuscate --recursive ./multi_cred_verifier_python/__init__.py`.  This will create a new `dist` folder in the existing `dist` folder

- Delete the `multi_cred_verifier_python` folder

- Rename the new `dist` folder to `multi_cred_verifier_python`

- Navigate to the project's root and run `python3 -m wheel pack dist`.  This will create the new, encrypted wheel file in the root of the project that can be distributed to customers.
