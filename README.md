# Lab on Offensive Security Group 23

Authors:
- Antoni Nowaczyk 1934899
- Maja Waszak 1997521
- Milosz Janewski 1962736

This reporitory contains the ransomware prototype Locked Until Coins Arrive (LUCA). For specification see the Report. 

Warning! This code is meant for inspection only. Run it on your own risk, solely in controlled environment (Windows VM). Executing the compiled LUCA code leads to file encryption in Pictures directory. This may result in irrevertible file loss. Manual decryption is possible. For safety, the encrypted AES key is stored in `aes_enc.bin`. Decrypt the key with `private_key.pem` to get plaintext AES key.

### Directory structure ### 

Subdirectory `dll_injection` contains the complete code of LUCA: sourcecode in `src`, header files in `include` and example RSA keys in `keys`. 
The `Makefile` contains hardcoded Mbed-TLS paths for MSYS32 MINGW64. 

Subdirectory `reflective_dll_injection` contains the incomplete Reflective DLL Injector code (see report). 

`server.py` is the simulated attacker server module, written in Python Flask. It runs on local host and must run when LUCA is executed. 