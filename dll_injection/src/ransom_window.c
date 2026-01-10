#include "ransom_window.h"
#include "windows.h"

const char g_szClassName[] = "RansomeWindow";

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
        case WM_CREATE:
        {
        // Create a static text control (label)
        HWND hwndText = CreateWindow(
            "STATIC",               // Predefined class for text
            "You've been ransomized! Pay 0.01BTC to this wallet: ", // Text to display
            WS_VISIBLE | WS_CHILD | SS_CENTER, // Styles
            20, 20,                 // x, y position
            260, 30,                // width, height
            hwnd,                   // parent window
            NULL,                   // no menu
            (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            NULL
        );

        // Create a button below the text
        HWND hwndButton = CreateWindow(
            "BUTTON",
            "Check payment",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            80, 70, 120, 40,
            hwnd,
            (HMENU)1,
            (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            NULL
        );
    }
    break;
        case WM_COMMAND:
            if (LOWORD(wParam) == 1)
                MessageBox(hwnd, "You paid the ransom.", "Message", MB_OK | MB_ICONINFORMATION);
        break;

        case WM_CLOSE:
            DestroyWindow(hwnd);
        break;

        case WM_DESTROY:
            PostQuitMessage(0);
        break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Function to create and run the window
int CreateMyWindow(HINSTANCE hInstance, int nCmdShow)
{
    WNDCLASSEX wc = {0};
    HWND hwnd;
    MSG Msg;

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = g_szClassName;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if(!RegisterClassEx(&wc))
    {
        MessageBox(NULL, "Window Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    hwnd = CreateWindowEx(
        0,
        g_szClassName,
        "You've been ransomized!",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 200,
        NULL, NULL, hInstance, NULL
    );

    if(hwnd == NULL)
    {
        MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while(GetMessage(&Msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }

    return (int)Msg.wParam;
}
