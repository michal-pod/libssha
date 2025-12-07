/*
 * This file is part of libssha - C++ SSH Agent Library
 * Copyright (C) 2025 Michał Podsiadlik <michal@nglab.net>
 *
 * libssha is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libssha is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libssha. If not, see <http://www.gnu.org/licenses/>.
 */

#include <libssha/utils/logger.h>
#include <libssha/agent/session.h>
#include <libssha/key/key-manager.h>
#include <libssha/providers/botan/botan-lock-provider.h>

using namespace nglab::libssha;

class TestSession : public Session
{
public:
    TestSession(std::string sPipeName) : LogEnabler("TestSession")
    {
        m_hPipe = CreateNamedPipeA(
            sPipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            512 * 1024,
            512 * 1024,
            0,
            nullptr);

        if (m_hPipe == INVALID_HANDLE_VALUE)
        {
            log.error("CreateNamedPipe failed");
            throw std::runtime_error("CreateNamedPipe failed");
        }

        m_hEventConnect = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        m_hEventRead = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        m_hEventWrite = CreateEventA(nullptr, TRUE, FALSE, nullptr);

        ZeroMemory(&m_ovConnect, sizeof(OVERLAPPED));
        ZeroMemory(&m_ovRead, sizeof(OVERLAPPED));
        ZeroMemory(&m_ovWrite, sizeof(OVERLAPPED));
        m_ovConnect.hEvent = m_hEventConnect;

        BOOL bConnected = ConnectNamedPipe(m_hPipe, &m_ovConnect);
        DWORD dwError = GetLastError();
        if (!bConnected && dwError == ERROR_IO_PENDING)
        {
            log.info("Waiting for client to connect...");
        }
        else if (!bConnected && dwError == ERROR_PIPE_CONNECTED)
        {
            SetEvent(m_hEventConnect);
        }
    }

    ~TestSession()
    {
        if (m_hPipe && m_hPipe != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(m_hPipe);
            DisconnectNamedPipe(m_hPipe);
            CloseHandle(m_hPipe);
        }

        if (m_hEventConnect)
            CloseHandle(m_hEventConnect);
        if (m_hEventRead)
            CloseHandle(m_hEventRead);
        if (m_hEventWrite)
            CloseHandle(m_hEventWrite);

        log.info("TestSession destroyed");
    }

    bool confirmRequest(const KeyBase &key) override
    {
        std::string question;
        question += "A request to perform an action has been received.\n";
        if (m_sClientPath.length() > 0)
        {
            std::string filename = m_sClientPath.substr(m_sClientPath.find_last_of("\\/") + 1);
            question += std::format("Requesting application: {} (PID={})\n", filename, m_ulClientPid);
        }
        question += std::format("Want to access key with {} with fingerprint {}?",
                                key.comment(), key.fingerprint());

        if (MessageBoxA(
                nullptr,
                question.c_str(),
                "SSH Agent Request",
                MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2 | MB_SYSTEMMODAL) != IDYES)
        {
            log.info("Request denied by user");
            return false;
        }

        log.info("Request confirmed");
        return true;
    }

    bool requiresConfirmation([[maybe_unused]] const KeyBasePtr key) const override
    {
        return false;
    }

    bool processExtensionMessage([[maybe_unused]] const ExtensionMessage &msg) override
    {
        return false;
    }

    std::string client() const override
    {
        std::string sFileName = m_sClientPath.substr(m_sClientPath.find_last_of("\\/") + 1);

        return sFileName;
    }

    bool send(secure_vector<uint8_t> &data) override
    {
        DWORD bytesWritten = 0;
        ResetEvent(m_hEventWrite);
        ZeroMemory(&m_ovWrite, sizeof(OVERLAPPED));
        m_ovWrite.hEvent = m_hEventWrite;
        BOOL bResult = WriteFile(m_hPipe, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, &m_ovWrite);
        if (!bResult && GetLastError() != ERROR_IO_PENDING)
        {
            log.error("Failed to write to pipe");
            return false;
        }

        return true;
    }

    bool getClientInfo()
    {
        ULONG ulPid = 0;
        if (!GetNamedPipeClientProcessId(m_hPipe, &ulPid))
        {
            log.error("GetNamedPipeClientProcessId failed");
            return false;
        }
        m_ulClientPid = ulPid;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_ulClientPid);
        if (!hProcess)
        {
            log.error("OpenProcess failed");
            return false;
        }

        char pathBuffer[MAX_PATH];
        DWORD pathSize = sizeof(pathBuffer);
        if (!QueryFullProcessImageNameA(hProcess, 0, pathBuffer, &pathSize))
        {
            log.error("QueryFullProcessImageName failed");
            CloseHandle(hProcess);
            return false;
        }
        m_sClientPath = pathBuffer;

        log.info("Client PID={}, Path={}", m_ulClientPid, m_sClientPath);

        CloseHandle(hProcess);
        return true;
    }

    bool checkUser(PSID pServerUserSid)
    {
        if (!ImpersonateNamedPipeClient(m_hPipe))
        {
            log.error("ImpersonateNamedPipeClient failed");
            return false;
        }

        HANDLE hThreadToken = nullptr;
        BOOL isTokenOpened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken);
        RevertToSelf();
        if (!isTokenOpened)
        {
            log.error("OpenThreadToken failed");
            return false;
        }

        DWORD tokenInfoLength = 0;
        GetTokenInformation(hThreadToken, TokenUser, nullptr, 0, &tokenInfoLength);
        std::vector<uint8_t> tokenInfoBuffer(tokenInfoLength);

        if (!GetTokenInformation(hThreadToken, TokenUser, tokenInfoBuffer.data(), tokenInfoLength, &tokenInfoLength))
        {
            log.error("GetTokenInformation failed");
            CloseHandle(hThreadToken);
            return false;
        }

        CloseHandle(hThreadToken);
        TOKEN_USER *tu = reinterpret_cast<TOKEN_USER *>(tokenInfoBuffer.data());
        BOOL same = EqualSid(tu->User.Sid, pServerUserSid);
        return same == TRUE;
    }

    void initRead()
    {
        m_readBuffer.resize(256 * 1024);
        ResetEvent(m_hEventRead);
        ZeroMemory(&m_ovRead, sizeof(OVERLAPPED));
        m_ovRead.hEvent = m_hEventRead;
        DWORD dwBytesRead = 0;
        if (!ReadFile(m_hPipe, m_readBuffer.data(), static_cast<DWORD>(m_readBuffer.size()), &dwBytesRead, &m_ovRead))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                log.error("ReadFile failed");
            }
        }
    }

    void onRead(DWORD dwBytesRead)
    {
        process(m_readBuffer.data(), dwBytesRead);
        initRead();
    }

    HANDLE hEventConnect() const { return m_hEventConnect; }
    HANDLE hEventRead() const { return m_hEventRead; }
    HANDLE hEventWrite() const { return m_hEventWrite; }

    OVERLAPPED *ovConnect() { return &m_ovConnect; }
    OVERLAPPED *ovRead() { return &m_ovRead; }
    OVERLAPPED *ovWrite() { return &m_ovWrite; }

    const std::string &clientPath() const { return m_sClientPath; }
    ULONG clientPid() const { return m_ulClientPid; }
    HANDLE pipeHandle() const { return m_hPipe; }

    bool onConnected()
    {
        // Handle connect event
        DWORD dwDummy;
        if (GetOverlappedResult(m_hPipe, &m_ovConnect, &dwDummy, FALSE))
        {
            log.info("Client connected: PID={}, Path={}", m_ulClientPid, m_sClientPath);
            ResetEvent(m_hEventConnect);
            getClientInfo();
            initRead();

            return true;
        }
        else
        {
            log.error("GetOverlappedResult failed for client PID={}", m_ulClientPid);
            return false;
        }
    }

    bool onRead()
    {
        log.info("Read event for client PID={}", m_ulClientPid);
        DWORD dwBytesRead = 0;
        if (GetOverlappedResult(m_hPipe, &m_ovRead, &dwBytesRead, FALSE))
        {
            log.info("Read {} bytes from client PID={}", dwBytesRead, m_ulClientPid);
            if (dwBytesRead > 0)
            {
                onRead(dwBytesRead);
                return true;
            }
            else
            {
                log.info("Client PID={} disconnected, dwBytesRead==0", m_ulClientPid);
                return false;
            }
        }
        else
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_BROKEN_PIPE || dwError == ERROR_PIPE_NOT_CONNECTED)
            {
                log.info("Client PID={} disconnected (pipe broken)", m_ulClientPid);
                return false;
            }
            else if (dwError != ERROR_IO_PENDING)
            {
                log.error("GetOverlappedResult failed for client PID={} with error: {}", m_ulClientPid, dwError);
                return false;
            }
        }

        return true;
    }

    bool onWritten()
    {
        log.info("Write event for client PID={}", m_ulClientPid);
        DWORD dwBytesWritten = 0;
        if (GetOverlappedResult(m_hPipe, &m_ovWrite, &dwBytesWritten, FALSE))
        {
            ResetEvent(m_hEventWrite);
            log.info("Wrote {} bytes to client PID={}", dwBytesWritten, m_ulClientPid);
            return true;
        }
        else
        {
            log.error("GetOverlappedResult failed for client PID={}", m_ulClientPid);
            return false;
        }
    }

private:
    HANDLE m_hPipe;
    HANDLE m_hEventConnect;
    HANDLE m_hEventRead;
    HANDLE m_hEventWrite;
    OVERLAPPED m_ovConnect;
    OVERLAPPED m_ovRead;
    OVERLAPPED m_ovWrite;
    std::string m_sClientPath;
    PSID m_sClientSid;
    ULONG m_ulClientPid{0};
    std::vector<uint8_t> m_readBuffer;
};

class PipeServer : public LogEnabler
{
public:
    PipeServer(const std::string &pipeName)
        : LogEnabler("PipeServer"), m_pipeName(pipeName)
    {
    }

    void disconnectClient(size_t index)
    {
        log.debug("Disconnecting client at index {}", index);
        if (index < m_Clients.size())
        {
            log.debug("Disconnecting client PID={}", m_Clients[index]->clientPid());
            m_Clients.erase(m_Clients.begin() + index);
        }
    }
    void run()
    {

        // Tworzymy pierwszego klienta
        m_Clients.push_back(std::make_unique<TestSession>(m_pipeName));

        while (true)
        {
            std::vector<HANDLE> vecHandles;
            vecHandles.clear();
            for (const auto &client : m_Clients)
            {
                vecHandles.push_back(client->hEventConnect());
                vecHandles.push_back(client->hEventRead());
                vecHandles.push_back(client->hEventWrite());
            }

            DWORD dwResult = WaitForMultipleObjects(
                static_cast<DWORD>(vecHandles.size()),
                vecHandles.data(),
                FALSE,
                1000); // 1 second timeout

            if (dwResult == WAIT_TIMEOUT)
            {
                // Timeout occurred, continue the loop
                continue;
            }
            // log.debug("WaitForMultipleObjects returned: {}", dwResult);

            if (dwResult >= WAIT_OBJECT_0 && dwResult < WAIT_OBJECT_0 + vecHandles.size())
            {
                size_t index = dwResult - WAIT_OBJECT_0;
                size_t clientIndex = index / 3;
                size_t eventType = index % 3;

                if (clientIndex >= m_Clients.size())
                {
                    log.error("Invalid client index: {}", clientIndex);
                    continue;
                }

                TestSession &client = *m_Clients[clientIndex];

                if (eventType == 0)
                {
                    log.debug("Connect event for client index {}", clientIndex);
                    if (client.onConnected())
                    {
                        // Create a new client for the next connection
                        m_Clients.push_back(std::make_unique<TestSession>(m_pipeName));
                        continue;
                    }
                }
                else if (eventType == 1)
                {
                    if (!client.onRead())
                    {
                        log.debug("Client PID={} disconnected, removing from list", client.clientPid());
                        disconnectClient(clientIndex);
                    }
                }
                else if (eventType == 2)
                {
                    if (!client.onWritten())
                    {
                        log.debug("Client PID={} write failed, removing from list", client.clientPid());
                        disconnectClient(clientIndex);
                    }
                }
            }
            else if (dwResult == WAIT_FAILED)
            {
                DWORD error = GetLastError();
                log.error("WaitForMultipleObjects failed with error: {}", error);
                if (error == ERROR_INVALID_HANDLE)
                {
                    log.error("Invalid handle detected. Rebuilding handle list...");
                    m_Clients.clear();
                    m_Clients.push_back(std::make_unique<TestSession>(m_pipeName));
                    continue; // Restart the loop to rebuild vecHandles
                }
                break; // Exit the loop for other critical errors
            }
            /*else {
                log.error("WaitForMultipleObjects failed with error: {}", GetLastError());
            }*/
        }
    }

private:
    std::string m_pipeName;
    std::vector<std::unique_ptr<TestSession>> m_Clients;
};

int main([[maybe_unused]] int argc, [[maybe_unused]] char *argv[])
{
    Logger::instance().info("Application started");

    [[maybe_unused]] auto &key_manager = KeyManager::instance();
    KeyFactory::initializeKeyTypes();
    ExtensionFactory::initializeExtensions();
    KeyManager::setLockProvider(new BotanLockProvider());

    Logger log(Logger::instance(), "test-agent");

    PipeServer server(R"(\\.\pipe\openssh-ssh-agent)");

    server.run();

    return 0;
}