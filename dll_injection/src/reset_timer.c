#include <windows.h>
#include <stdio.h>

#define REG_PATH  "Software\\FunEncryptionApp"
#define REG_VALUE "ExpiryTime"

int main(void)
{
    HKEY hKey;

    if (RegOpenKeyExA(
            HKEY_CURRENT_USER,
            REG_PATH,
            0,
            KEY_SET_VALUE,
            &hKey
        ) != ERROR_SUCCESS)
    {
        printf("Registry key not found\n");
        return 1;
    }

    if (RegDeleteValueA(hKey, REG_VALUE) != ERROR_SUCCESS)
    {
        printf("Value not found or could not be deleted\n");
        RegCloseKey(hKey);
        return 1;
    }

    RegCloseKey(hKey);
    printf("Timer value deleted successfully\n");
    return 0;
}
