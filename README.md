Cloud Key Store - secure storage for private credentials
========================================================

Introduction
------------

Cloud Key Store (CKS) is a tool to protect private cryptographic keys in the cloud.
It performs cryptographic operations using the keys based on user requests.
The user authentication is password based.
An example usage is to store GnuPG private keys.

A detailed discussion of our motivation, threat model, design decisions, and evaluation of the CKS is presented in our technical paper: [https://arxiv.org/abs/1804.08569](https://arxiv.org/abs/1804.08569)


Building instructions
---------------------

### Prerequisites

- Install SGX SDK:
  * Download and install [Intel SGX SDK for Linux](https://github.com/01org/linux-sgx)
  * Set the SGX_SDK variable in the Makefile to the location of your SGX SDK
  * Set the SIGNING_KEY variable in the Makefile to point to an enclave signing key. If needed, generate a signing key following Intel's [OpenSSL Examples](https://software.intel.com/en-us/node/708948)

- Build the 3rd party libraries
  * Clone [sgx-utils](https://github.com/SSGAalto/sgx-utils)
  * Build libraries by running `make`.
  * Copy them to `./libs` directory, or modify Makefile `Lib_Dir` variable.
  * The required libraries are `lib_tke` and `lib_uke`.

### Building CKS server

  * Make sure that the Makefile libdir variable points to the right directory (`sgx-utils/libs`), and the paths to the 3rd party libraries are correct.
  * Run `make`. This will generate objects under ``build`` directory and `keystore` and `client` executables. The enclave will be put under ``build/enclave``.
  * To test the build run `./keystore`, connect to the server by running `./client`.
  * To build tests run `cmake` in the `test` directory. Run `make check` to run the unit tests.

Installation
------------

In order verify the quote recieved during remote attestation, you need access to the Intel Attestation Service (IAS). 
This requires registering with Intel via [this form](https://software.intel.com/formfill/sgx-onboarding).
Once registered, set your assigned Service Provider ID (SPID) in the ias.cpp file.
