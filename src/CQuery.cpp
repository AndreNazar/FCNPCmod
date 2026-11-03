#include <winsock2.h>
#include "Main.hpp"
#include "CQuery.hpp"

extern logprintf_t logprintf;

typedef int (WSAAPI *SendTo_t)(
    SOCKET socket,
    const char *buffer,
    int length,
    int flags,
    const sockaddr *to,
    int tolen
);

static subhook_t g_sendtoHook = NULL;
static SendTo_t g_sendtoOriginal = NULL;
static volatile LONG g_queryLogCount = 0;

static int WSAAPI HookSendTo(
    SOCKET socket,
    const char *buffer,
    int length,
    int flags,
    const sockaddr *to,
    int tolen
)
{
    if (buffer && length >= 13 &&
        memcmp(buffer, "SAMP", 4) == 0 &&
        (buffer[10] == 'c' || buffer[10] == 'd'))
    {
        WORD count = 0;
        memcpy(&count, buffer + 11, sizeof(count));

        LONG logCount = InterlockedIncrement(&g_queryLogCount);

        if (logCount <= 10) {
            logprintf(
                "[FCNPC] Query response: opcode=%c, entries=%u, bytes=%d",
                buffer[10],
                count,
                length
            );
        }
    }

    return g_sendtoOriginal(
        socket,
        buffer,
        length,
        flags,
        to,
        tolen
    );
}

bool CQuery::Initialize()
{
    HMODULE hWinsock = GetModuleHandleA("ws2_32.dll");

    if (!hWinsock) {
        hWinsock = LoadLibraryA("ws2_32.dll");
    }

    if (!hWinsock) {
        logprintf("[FCNPC] Query: unable to load ws2_32.dll");
        return false;
    }

    FARPROC pSendTo = GetProcAddress(hWinsock, "sendto");

    if (!pSendTo) {
        logprintf("[FCNPC] Query: sendto not found");
        return false;
    }

    g_sendtoHook = subhook_new(
        reinterpret_cast<void*>(pSendTo),
        reinterpret_cast<void*>(HookSendTo),
        static_cast<subhook_flags_t>(0)
    );

    if (!g_sendtoHook) {
        logprintf("[FCNPC] Query: subhook creation failed");
        return false;
    }

    g_sendtoOriginal = reinterpret_cast<SendTo_t>(
        subhook_get_trampoline(g_sendtoHook)
    );

    if (!g_sendtoOriginal) {
        logprintf("[FCNPC] Query: trampoline creation failed");
        subhook_free(g_sendtoHook);
        g_sendtoHook = NULL;
        return false;
    }

    if (subhook_install(g_sendtoHook) != 0) {
        logprintf("[FCNPC] Query: hook installation failed");
        subhook_free(g_sendtoHook);
        g_sendtoHook = NULL;
        g_sendtoOriginal = NULL;
        return false;
    }

    logprintf("[FCNPC] Query: sendto hook installed");
    return true;
}
