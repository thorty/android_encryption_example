# Service Class for Encrypt and Decrypt Data in Android

Simple Service Class for the use of encryption in your android app. 

Random Encryption For 245 Bytes. (can be used for Auth-Tokens ore maybe an AES Key)

Using Android KeyStore to generate and Store the Random Keys. 
Use the given Methods for encryption an decryption of a String with 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'.

depends:
minSdkVersion 23

## How to use

Just Copy EncryptionService.java and HaveFun.

## License

Copyright 2016 Thorsten Weiskopf

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
