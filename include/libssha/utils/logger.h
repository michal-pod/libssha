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
#pragma once
#include <string>
#include <format>
#include <functional>
namespace nglab
{
    namespace libssha
    {
        /**
         * @brief Logger class for logging messages with different severity levels.
         * 
         * Typical usage:
         * @code
         * auto& log = Logger::instance();
         * log.info("This is an info message: {}", info_detail);
         * log.error("An error occurred: {}", error_detail);
         * 
         * auto& log_with_name = Logger(Logger::instance(), "MyModule");
         * log_with_name.debug("Debug message from MyModule: {}", debug_detail);
         * @endcode
         */
        class Logger
        {
        public:            
            enum Level {
                Error = 0,
                Warning,
                Info,
                Trace,
                Debug,
                VDebug
            };

            // Type definition for the log callback function
            using LogCallback = std::function<void(Level, const std::string_view&, const std::string_view&)>;

            /**
             * @brief Construct a new Logger object with a parent logger and a name.
             * @param parent The parent logger.
             * @param name The name of this logger.
             */
            Logger(const Logger&, std::string name);


            /**
             * @brief Get the singleton instance of the Logger.
             * @return Logger& The singleton Logger instance.
             */
            static Logger &instance();

            /**
             * @brief Log error message. Using C++20 std::format for formatting.
             */
            template <typename... Args> void error(std::format_string<Args...> format, Args&&... args) const {
                log(Level::Error, std::format(format, std::forward<Args>(args)...));
            }

            /**
             * @brief Log warning message. Using C++20 std::format for formatting.
             */
            template <typename... Args> void warning(std::format_string<Args...> format, Args&&... args) const {
                log(Level::Warning, std::format(format, std::forward<Args>(args)...));
            }

            /**
             * @brief Log info message. Using C++20 std::format for formatting.
             */
            template <typename... Args> void info(std::format_string<Args...> format, Args&&... args) const {
                log(Level::Info, std::format(format, std::forward<Args>(args)...));
            }

            /** 
             * @brief Log trace message. Using C++20 std::format for formatting.
             */
            template <typename... Args> void trace(std::format_string<Args...> format, Args&&... args) const {
                log(Level::Trace, std::format(format, std::forward<Args>(args)...));
            }

            /**
             * @brief Log debug message. Using C++20 std::format for formatting.
             */
            template <typename... Args> void debug(std::format_string<Args...> format, Args&&... args) const {
                log(Level::Debug, std::format(format, std::forward<Args>(args)...));
            }

            /**
             * @brief Log verbose-debug (vdebug) message. Using C++20 std::format for formatting.
             */
            template <typename... Args> void vdebug(std::format_string<Args...> format, Args&&... args) const {
                log(Level::VDebug, std::format(format, std::forward<Args>(args)...));
            }

            /**
             * @brief Log a message with the given level and message.
             * 
             * This function is responsible for actually logging the message to the appropriate output
             * and should be used only internally by the other logging functions.
             * 
             * @param level The severity level of the log message.
             * @param message The log message.
             * @param logger_name The name of the logger (optional).
             */
            void log(Level level, std::string_view message, std::string_view logger_name = "") const;

            /**
             * @brief Set callback function for log messages.
             * @param callback The callback function to be called on log messages.
             * 
             * The callback function should have the signature:
             * void callback(Level level, const std::string_view& logger_name, const std::string_view& message)
             */
            void setLogCallback(LogCallback callback) {
                m_callback = callback;
            }

            /**
             * @brief Set logger level.
             * @param level The minimum level of messages to log.             
             */
            void setLevel(Level level) {
                m_level = level;
            }

            /**
             * @brief Get current logger level.
             * @return Level The current logger level.
             */
            Level getLevel() const {
                return m_level;
            }


            /**
             * @brief Get the name of the level as a string.
             * @param level The log level.
             */
            static const char* getLevelName(Level level);

        private:
            Logger();
            Logger* m_parent;
            std::string m_name;
            bool m_colors_enabled{true};
            Level m_level{Level::Info};
            LogCallback m_callback{nullptr};
        };

        /**
         * @brief Helper class to enable logging in other classes.
         * This class provides a protected member `log` that can be used
         * to log messages with given logger name.
         * 
         * Typical usage:
         * @code
         * class MyClass : public LogEnabler {
         * public:
         *    MyClass() : LogEnabler("MyClass") {}
         *     void doSomething() {
         *         log.info("Doing something in MyClass");
         *     }
         * };
         * @endcode
         */
        class LogEnabler
        {
        public:
            LogEnabler(std::string name)
                : log(Logger::instance(), name)
            {
            }
        protected:
            Logger log;
        };
    } // namespace libssha
} // namespace nglab