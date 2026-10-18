/*
 * This file is part of libssha - C++ SSH Agent Library
 * Copyright (C) 2026 Michał Podsiadlik <michal@nglab.net>
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
#include "process.h"
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

extern char **environ;

namespace nglab::libssha::test::integration
{
    namespace detail
    {
        // The current environment with the given variables replaced
        std::vector<std::string> mergeEnvironment(const Environment &env)
        {
            Environment merged;
            for (char **var = environ; *var != nullptr; ++var)
            {
                std::string entry(*var);
                auto pos = entry.find('=');
                if (pos != std::string::npos)
                {
                    merged[entry.substr(0, pos)] = entry.substr(pos + 1);
                }
            }
            for (const auto &[name, value] : env)
            {
                merged[name] = value;
            }

            std::vector<std::string> result;
            for (const auto &[name, value] : merged)
            {
                result.push_back(name + "=" + value);
            }
            return result;
        }

        std::vector<char *> pointers(std::vector<std::string> &strings)
        {
            std::vector<char *> result;
            for (auto &s : strings)
            {
                result.push_back(s.data());
            }
            result.push_back(nullptr);
            return result;
        }

        pid_t spawn(const std::vector<std::string> &args, const Environment &env, posix_spawn_file_actions_t &actions)
        {
            auto argStrings = args;
            auto envStrings = mergeEnvironment(env);
            auto argv = pointers(argStrings);
            auto envp = pointers(envStrings);

            pid_t pid = -1;
            int rc = posix_spawn(&pid, argv[0], &actions, nullptr, argv.data(), envp.data());
            if (rc != 0)
            {
                throw std::runtime_error("posix_spawn " + args[0] + ": " + std::strerror(rc));
            }
            return pid;
        }

        int exitCode(int status)
        {
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
    }

    ProcessResult runProcess(const std::vector<std::string> &args, const Environment &env,
                             const std::string &stdinFile, std::chrono::milliseconds timeout)
    {
        int outPipe[2];
        int errPipe[2];
        if (pipe2(outPipe, O_CLOEXEC) != 0 || pipe2(errPipe, O_CLOEXEC) != 0)
        {
            throw std::runtime_error("pipe: " + std::string(std::strerror(errno)));
        }

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, stdinFile.c_str(), O_RDONLY, 0);
        posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, errPipe[1], STDERR_FILENO);
        pid_t pid = -1;
        try
        {
            pid = detail::spawn(args, env, actions);
        }
        catch (...)
        {
            posix_spawn_file_actions_destroy(&actions);
            close(outPipe[0]);
            close(outPipe[1]);
            close(errPipe[0]);
            close(errPipe[1]);
            throw;
        }
        posix_spawn_file_actions_destroy(&actions);
        close(outPipe[1]);
        close(errPipe[1]);

        ProcessResult result;
        pollfd fds[2] = {{outPipe[0], POLLIN, 0}, {errPipe[0], POLLIN, 0}};
        std::string *targets[2] = {&result.out, &result.err};
        int open = 2;
        bool killed = false;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (open > 0)
        {
            auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            if (left.count() <= 0)
            {
                // Children of the process (sshd started by ssh) may keep the pipes open
                kill(pid, SIGKILL);
                killed = true;
                break;
            }
            if (poll(fds, 2, static_cast<int>(left.count())) < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            for (int i = 0; i < 2; ++i)
            {
                if (fds[i].fd < 0 || (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0)
                    continue;
                char buffer[4096];
                ssize_t n = read(fds[i].fd, buffer, sizeof(buffer));
                if (n > 0)
                {
                    targets[i]->append(buffer, n);
                }
                else
                {
                    close(fds[i].fd);
                    fds[i].fd = -1;
                    --open;
                }
            }
        }
        for (auto &fd : fds)
        {
            if (fd.fd >= 0)
                close(fd.fd);
        }

        int status = 0;
        waitpid(pid, &status, 0);
        result.exitCode = killed ? -1 : detail::exitCode(status);
        if (killed)
        {
            result.err += "\n[killed after timeout]";
        }
        return result;
    }

    BackgroundProcess::BackgroundProcess(const std::vector<std::string> &args, const Environment &env,
                                         const std::string &logFile)
    {
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, logFile.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO);
        try
        {
            m_pid = detail::spawn(args, env, actions);
        }
        catch (...)
        {
            posix_spawn_file_actions_destroy(&actions);
            throw;
        }
        posix_spawn_file_actions_destroy(&actions);
    }

    BackgroundProcess::~BackgroundProcess()
    {
        stop();
    }

    bool BackgroundProcess::running()
    {
        if (m_pid < 0)
            return false;
        int status = 0;
        if (waitpid(m_pid, &status, WNOHANG) == m_pid)
        {
            m_pid = -1;
            return false;
        }
        return true;
    }

    void BackgroundProcess::stop()
    {
        if (!running())
            return;

        // SIGTERM lets the agent flush coverage data, SIGKILL if it hangs
        kill(m_pid, SIGTERM);
        for (int i = 0; i < 50; ++i)
        {
            if (!running())
                return;
            usleep(100 * 1000);
        }
        kill(m_pid, SIGKILL);
        waitpid(m_pid, nullptr, 0);
        m_pid = -1;
    }
}
