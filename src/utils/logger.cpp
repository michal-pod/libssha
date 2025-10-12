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
#include <format>
#include <cstdarg>
#include <chrono>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#endif

namespace nglab
{
    namespace libssha
    {

        Logger::Logger() : m_parent(nullptr)
        {
            char *env_p = std::getenv("LIBSSHA_LOG_COLORS");
            if (env_p && std::string(env_p) == "0")
            {
                m_colors_enabled = false;
            }
            env_p = std::getenv("LIBSSHA_LOG_LEVEL");
            if (env_p)
            {
                std::string level_str(env_p);
                level_str = level_str.substr(0, 3);
                std::transform(level_str.begin(), level_str.end(), level_str.begin(), ::toupper);
                if (level_str == "ERR")
                {
                    m_level = Level::Error;
                }
                else if (level_str == "WAR")
                {
                    m_level = Level::Warning;
                }
                else if (level_str == "INF")
                {
                    m_level = Level::Info;
                }
                else if (level_str == "TRA")
                {
                    m_level = Level::Trace;
                }
                else if (level_str == "DEB")
                {
                    m_level = Level::Debug;
                }
                else if (level_str == "VDE")
                {
                    m_level = Level::VDebug;
                }
            }
        }

        Logger::Logger(const Logger &other, std::string name)
            : m_parent(const_cast<Logger *>(&other)), m_name(name)
        {
        }

        Logger &Logger::instance()
        {
            static Logger instance;
            return instance;
        }

        void Logger::log(Level level, std::string_view message, std::string_view logger_name) const
        {
            if (m_parent)
            {
                m_parent->log(level, message, m_name);
                return;
            }

            if (m_callback)
            {
                m_callback(level, message, logger_name);
                return;
            }

            if (level > m_level)
            {
                return;
            }

            const char *color_code = "";
            const char *reset_code = "\033[0m";
            switch (level)
            {
            case Level::Error:
                color_code = "\033[31m";
                break; // Red
            case Level::Warning:
                color_code = "\033[33m";
                break; // Yellow
            case Level::Info:
                color_code = "\033[32m";
                break; // Green
            case Level::Trace:
                color_code = "\033[36m";
                break; // Cyan
            case Level::Debug:
                color_code = "\033[35m";
                break; // Magenta
            case Level::VDebug:
                color_code = "\033[90m";
                break; // Bright Black / Grey
            }
            if (!m_colors_enabled)
            {
                color_code = "";
                reset_code = "";
            }
            // Generate timestamp in format YYYYMMDD HH:MM:SS.mmm+TZ:TZ
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

            std::tm local_tm;
#ifdef _WIN32
            localtime_s(&local_tm, &time_t_now);
#else
            localtime_r(&time_t_now, &local_tm);
#endif

            char tz_sign = '+';
            int tz_hour = 0, tz_min = 0;
#if defined(__unix__) || defined(__APPLE__)
            long gmtoff = local_tm.tm_gmtoff;
            if (gmtoff < 0)
            {
                tz_sign = '-';
                gmtoff = -gmtoff;
            }
            tz_hour = static_cast<int>(gmtoff / 3600);
            tz_min = static_cast<int>((gmtoff % 3600) / 60);
#elif defined(_WIN32)
            // Windows: _get_timezone returns seconds west of UTC
            long timezone_sec = 0;
            _get_timezone(&timezone_sec);
            if (timezone_sec > 0)
            {
                tz_sign = '-';
            }
            else
            {
                tz_sign = '+';
                timezone_sec = -timezone_sec;
            }
            tz_hour = static_cast<int>(timezone_sec / 3600);
            tz_min = static_cast<int>((timezone_sec % 3600) / 60);
#endif

            std::string timestamp = std::format(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}{}{:02}:{:02}",
                local_tm.tm_year + 1900,
                local_tm.tm_mon + 1,
                local_tm.tm_mday,
                local_tm.tm_hour,
                local_tm.tm_min,
                local_tm.tm_sec,
                static_cast<int>(ms.count()),
                tz_sign,
                tz_hour,
                tz_min);
            const char *level_str = getLevelName(level);
#ifdef _WIN32
            // On Windows, also log to OutputDebugString
            std::string debug_message;
            if (logger_name.empty())
            {
                debug_message = std::format("[{}] {}", level_str, message);
            }
            else
            {
                debug_message = std::format("[{}] {}: {}", level_str, logger_name, message);
            }
            OutputDebugString(debug_message.c_str());
#endif
            if (logger_name.empty())
            {
                fprintf(stderr, "%s %s[%7s]%s %s\n", timestamp.c_str(), color_code, level_str, reset_code, message.data());
            }
            else
            {
                fprintf(stderr, "%s %s[%7s]%s %s: %s\n", timestamp.c_str(), color_code, level_str, reset_code, logger_name.data(), message.data());
            }
        }

        const char *Logger::getLevelName(Level level)
        {
            switch (level)
            {
            case Level::Error:
                return "ERROR";
            case Level::Warning:
                return "WARNING";
            case Level::Info:
                return "INFO";
            case Level::Trace:
                return "TRACE";
            case Level::Debug:
                return "DEBUG";
            case Level::VDebug:
                return "VDEBUG";
            default:
                return "UNKNOWN";
            }
        }
    } // namespace libssha
} // namespace nglab