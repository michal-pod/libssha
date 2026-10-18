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
#pragma once

#include <sys/types.h>
#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace nglab::libssha::test::integration
{
    using Environment = std::map<std::string, std::string>;

    struct ProcessResult
    {
        int exitCode = -1; // -1 when the process was killed
        std::string out;
        std::string err;

        // Both streams, for assertions on messages that ssh prints to either of them
        std::string output() const { return out + err; }
    };

    // Runs a program to completion with its output captured
    ProcessResult runProcess(const std::vector<std::string> &args, const Environment &env,
                             std::chrono::milliseconds timeout = std::chrono::seconds(30));

    // A process running in the background, terminated when the object goes away
    class BackgroundProcess
    {
    public:
        BackgroundProcess(const std::vector<std::string> &args, const Environment &env, const std::string &logFile);
        ~BackgroundProcess();

        BackgroundProcess(const BackgroundProcess &) = delete;
        BackgroundProcess &operator=(const BackgroundProcess &) = delete;

        bool running();
        void stop();

    private:
        pid_t m_pid = -1;
    };
}
