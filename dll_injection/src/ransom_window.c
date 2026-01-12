#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "comctl32.lib")

#define EXPIRY_FILE "expiry_time.txt"
#define SECONDS_24H (24 * 60 * 60)
#define TIMER_ID 1
#define REG_PATH  "Software\\FunEncryptionApp"
#define REG_VALUE "ExpiryTime"

time_t gExpiryTime = 0;

const char g_szClassName[] = "RansomwareWindow";

// Global handles
HFONT hTitleFont;
HFONT hTextFont;
HWND hStatusBar;
HWND hTimerLabel;

int EnsureExpiryTimeExists(void)
{
    HKEY hKey;
    DWORD disposition;

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

    // If key already existed, do nothing
    if (disposition == REG_OPENED_EXISTING_KEY)
    {
        RegCloseKey(hKey);
        return 1;
    }

    // First run: write expiry time
    time_t now = time(NULL);
    ULONGLONG expiry = (ULONGLONG)(now + SECONDS_24H);

    RegSetValueExA(
        hKey,
        REG_VALUE,
        0,
        REG_QWORD,
        (BYTE *)&expiry,
        sizeof(expiry)
    );

    RegCloseKey(hKey);
    return 1;
}

time_t ReadExpiryTime(void)
{
    HKEY hKey;
    ULONGLONG expiry = 0;
    DWORD size = sizeof(expiry);

    if (RegOpenKeyExA(
            HKEY_CURRENT_USER,
            REG_PATH,
            0,
            KEY_READ,
            &hKey
        ) != ERROR_SUCCESS)
    {
        return 0;
    }

    if (RegGetValueA(
            hKey,
            NULL,
            REG_VALUE,
            RRF_RT_REG_QWORD,
            NULL,
            &expiry,
            &size
        ) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 0;
    }

    RegCloseKey(hKey);
    return (time_t)expiry;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hLabelTitle;
    static HWND hLabelText;
    static HWND hBtnOk;
    static HWND hBtnCancel;
    static HWND hGroup;

    switch (msg)
    {
    case WM_CREATE:
    {
        EnsureExpiryTimeExists();

        gExpiryTime = ReadExpiryTime();
        SetTimer(hwnd, TIMER_ID, 1000, NULL);

        // Initialize common controls (status bar)
        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_BAR_CLASSES };
        InitCommonControlsEx(&icex);

        // Fonts
        hTitleFont = CreateFont(
            22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, "Segoe UI");

        hTextFont = CreateFont(
            16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, "Segoe UI");

        // Group box
        hGroup = CreateWindow(
            "BUTTON",
            "Information",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            15, 15, 440, 220,
            hwnd, NULL, NULL, NULL
        );

        // Title
        hLabelTitle = CreateWindow(
            "STATIC",
            "You've been ransomized!",
            WS_CHILD | WS_VISIBLE,
            30, 40, 400, 30,
            hwnd, NULL, NULL, NULL
        );
        SendMessage(hLabelTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

        hLabelText = CreateWindow(
            "EDIT",
            "Your files are encrypted. Yappa yappa \r\n\r\n"
            "yappa yappa \r\n\r\n"
            "yappa yappa \r\n\r\n"
            "yappa yappa \r\n\r\n"
            "yappa yappa \r\n\r\n"
            "yappa yappa \r\n\r\n",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            30, 80, 400, 110,
            hwnd, NULL, NULL, NULL
        );
        SendMessage(hLabelText, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        hTimerLabel = CreateWindow(
            "STATIC",
            "Loading timer",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            30, 200, 400, 25,   // positioned below the edit control
            hwnd, NULL, NULL, NULL
        );

        SendMessage(hTimerLabel, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        // Buttons
        hBtnOk = CreateWindow(
            "BUTTON",
            "Check payment",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            260, 240, 120, 40,
            hwnd, (HMENU)1, NULL, NULL
        );
        HMENU hMenu = GetSystemMenu(hwnd, FALSE); 
        if (hMenu)
        {
            // Remove close button
            DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
            DrawMenuBar(hwnd); // update title bar
        }
    }
    break;

    case WM_SIZE:
    {
        // Resize status bar automatically
        SendMessage(hStatusBar, WM_SIZE, 0, 0);
    }
    break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case 1:
            MessageBox(hwnd, "You clicked OK!", "Info", MB_OK | MB_ICONINFORMATION);
            SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)"OK clicked");
            break;

        case 2:
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            break;
        }
        break;
    case WM_TIMER:
    {
        if (wParam == TIMER_ID)
        {
            time_t now = time(NULL);
            long remaining = (long)difftime(gExpiryTime, now);

            char buf[128];

            if (remaining <= 0)
            {
                KillTimer(hwnd, TIMER_ID);
                strcpy(buf, "Time expired");
            }
            else
            {
                int h = remaining / 3600;
                int m = (remaining % 3600) / 60;
                int s = remaining % 60;

                sprintf(
                    buf,
                    "Time remaining: %02d:%02d:%02d",
                    h, m, s
                );
            }

            SetWindowText(hTimerLabel, buf);
        }
    }
    break;
    case WM_DESTROY:
        KillTimer(hwnd, TIMER_ID);
        DeleteObject(hTitleFont);
        DeleteObject(hTextFont);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int CreateMyWindow(HINSTANCE hInstance, int nCmdShow)
{
    WNDCLASSEX wc = { 0 };
    HWND hwnd;
    MSG Msg;

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = g_szClassName;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassEx(&wc);

    hwnd = CreateWindowEx(
        0,
        g_szClassName,
        "Nasty computer virus",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        500, 350,
        NULL, NULL, hInstance, NULL
    );

    while (GetMessage(&Msg, NULL, 0, 0))
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }
    return (int)Msg.wParam;
}
