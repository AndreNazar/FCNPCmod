
#if defined(WIN32)
    #include <winsock2.h>
#elif defined(LINUX)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <dlfcn.h>
#else
    #error Unsupported platform
#endif

#include "Main.hpp"
#include "CQuery.hpp"

#if defined(WIN32)

typedef int (WSAAPI *SendTo_t)(
    SOCKET socket,
    const char *buffer,
    int length,
    int flags,
    const sockaddr *to,
    int tolen
);

#elif defined(LINUX)

typedef ssize_t (*SendTo_t)(
    int socket,
    const void *buffer,
    size_t length,
    int flags,
    const sockaddr *to,
    socklen_t tolen
);

#endif

static subhook_t g_sendtoHook = NULL;
static SendTo_t g_sendtoOriginal = NULL;

#if defined(LINUX)
static void *g_libcHandle = NULL;
#endif

static void AppendUInt32(std::vector<char> &buffer, DWORD value)
{
    buffer.push_back(static_cast<char>(value & 0xFF));
    buffer.push_back(static_cast<char>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<char>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<char>((value >> 24) & 0xFF));
}

static bool AppendNpcEntries(
    const char *packet,
    size_t packetLength,
    std::vector<char> &modified,
    WORD &added
)
{
    added = 0;

    if (!packet || packetLength < 13)
        return false;

    if (memcmp(packet, "SAMP", 4) != 0)
        return false;

    const char opcode = packet[10];

    if (opcode != 'c' && opcode != 'd')
        return false;

    WORD playerCount =
        static_cast<unsigned char>(packet[11]) |
        (static_cast<WORD>(
            static_cast<unsigned char>(packet[12])
        ) << 8);

    size_t offset = 13;

    for (WORD i = 0; i < playerCount; i++)
    {
        if (opcode == 'c')
        {
            if (offset >= packetLength)
                return false;

            BYTE nameLength =
                static_cast<unsigned char>(packet[offset]);

            offset++;

            if (nameLength > MAX_PLAYER_NAME)
                return false;

            if (packetLength - offset < nameLength + 4)
                return false;

            offset += nameLength + 4;
        }
        else
        {
            if (packetLength - offset < 2)
                return false;

            offset++;

            BYTE nameLength =
                static_cast<unsigned char>(packet[offset]);

            offset++;

            if (nameLength > MAX_PLAYER_NAME)
                return false;

            if (packetLength - offset < nameLength + 8)
                return false;

            offset += nameLength + 8;
        }
    }

    if (offset != packetLength)
        return false;

    if (!pServer || !pNetGame || !pNetGame->pPlayerPool)
        return false;

    CPlayerManager *pPlayerManager =
        pServer->GetPlayerManager();

    if (!pPlayerManager)
        return false;

    modified.assign(packet, packet + packetLength);

    WORD newCount = playerCount;
    const size_t MAX_QUERY_PACKET_SIZE = 65507;

    for (WORD npcId : pPlayerManager->m_vNpcID)
    {
        if (npcId >= MAX_PLAYERS)
            continue;

        if (opcode == 'd' && npcId > 255)
            continue;

        CPlayerData *pNpc = pPlayerManager->GetAt(npcId);

        if (!pNpc)
            continue;

        char nickname[MAX_PLAYER_NAME + 1] = {};

        pNpc->GetName(nickname, sizeof(nickname));

        size_t nameLength = strlen(nickname);

        if (nameLength == 0 || nameLength > MAX_PLAYER_NAME)
            continue;

        if (newCount == 0xFFFF)
            break;

        size_t entrySize = opcode == 'c'
            ? 1 + nameLength + 4
            : 2 + nameLength + 8;

        if (modified.size() > MAX_QUERY_PACKET_SIZE)
            break;

        if (entrySize > MAX_QUERY_PACKET_SIZE - modified.size())
            break;

        DWORD score = pNetGame->pPlayerPool->dwScore[npcId];

        if (opcode == 'c')
        {
            modified.push_back(static_cast<char>(nameLength));

            modified.insert(
                modified.end(),
                nickname,
                nickname + nameLength
            );

            AppendUInt32(modified, score);
        }
        else
        {
            modified.push_back(static_cast<char>(npcId));
            modified.push_back(static_cast<char>(nameLength));

            modified.insert(
                modified.end(),
                nickname,
                nickname + nameLength
            );

            AppendUInt32(modified, score);
            AppendUInt32(modified, 0);
        }

        newCount++;
        added++;
    }

    if (added == 0)
    {
        modified.clear();
        return false;
    }

    modified[11] = static_cast<char>(newCount & 0xFF);
    modified[12] = static_cast<char>((newCount >> 8) & 0xFF);

    return true;
}

#if defined(WIN32)

static int WSAAPI HookSendTo(
    SOCKET socket,
    const char *buffer,
    int length,
    int flags,
    const sockaddr *to,
    int tolen
)
{
    const char *sendBuffer = buffer;
    int sendLength = length;

    std::vector<char> modified;
    WORD added = 0;

    if (buffer && length > 0)
    {
        if (AppendNpcEntries(
            buffer,
            static_cast<size_t>(length),
            modified,
            added
        ))
        {
            sendBuffer = modified.data();
            sendLength = static_cast<int>(modified.size());
        }
    }

    return g_sendtoOriginal(
        socket,
        sendBuffer,
        sendLength,
        flags,
        to,
        tolen
    );
}

#elif defined(LINUX)

static ssize_t HookSendTo(
    int socket,
    const void *buffer,
    size_t length,
    int flags,
    const sockaddr *to,
    socklen_t tolen
)
{
    const void *sendBuffer = buffer;
    size_t sendLength = length;

    std::vector<char> modified;
    WORD added = 0;

    if (buffer)
    {
        if (AppendNpcEntries(
            static_cast<const char *>(buffer),
            length,
            modified,
            added
        ))
        {
            sendBuffer = modified.data();
            sendLength = modified.size();
        }
    }

    return g_sendtoOriginal(
        socket,
        sendBuffer,
        sendLength,
        flags,
        to,
        tolen
    );
}

#endif

bool CQuery::Initialize()
{
    if (g_sendtoHook)
        return true;

    void *pSendTo = NULL;

#if defined(WIN32)

    HMODULE hWinsock = GetModuleHandleA("ws2_32.dll");

    if (!hWinsock)
        hWinsock = LoadLibraryA("ws2_32.dll");

    if (!hWinsock)
        return false;

    pSendTo = reinterpret_cast<void *>(
        GetProcAddress(hWinsock, "sendto")
    );

    if (!pSendTo)
        return false;

#elif defined(LINUX)

    g_libcHandle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);

    if (!g_libcHandle)
        return false;

    pSendTo = dlsym(g_libcHandle, "sendto");

    if (!pSendTo)
        return false;

#endif

    g_sendtoHook = subhook_new(
        pSendTo,
        reinterpret_cast<void *>(HookSendTo),
        static_cast<subhook_flags_t>(0)
    );

    if (!g_sendtoHook)
        return false;

    g_sendtoOriginal = reinterpret_cast<SendTo_t>(
        subhook_get_trampoline(g_sendtoHook)
    );

    if (!g_sendtoOriginal)
    {
        subhook_free(g_sendtoHook);
        g_sendtoHook = NULL;
        return false;
    }

    if (subhook_install(g_sendtoHook) != 0)
    {
        subhook_free(g_sendtoHook);
        g_sendtoHook = NULL;
        g_sendtoOriginal = NULL;
        return false;
    }

    return true;
}
