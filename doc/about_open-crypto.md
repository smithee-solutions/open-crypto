### test vectors ###


Cipher = AES-128-GCM
Key = feffe9928665731c6d6a8f9467308308
IV = cafebabefacedbaddecaf888
Plaintext = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
Ciphertext = 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985
AAD =
Tag = 4d5c2af327cd64a62cf35abd2ba6fab4

from boringssl/crypto/cipher_extra/test/cipher_tests.txt

### about naming ###

it's libeac-crypto_<variant>.

debian package rules disallow underscore so the package name
is libeac-crypto-<variant>


