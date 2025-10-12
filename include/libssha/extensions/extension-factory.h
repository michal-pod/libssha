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
#include <libssha/utils/deserializer.h>
#include <unordered_map>
#include <string>
#include <functional>
#include <memory>
namespace nglab
{
    namespace libssha
    {
        class ExtensionBase;
        /**
         * @brief Factory class for creating extension instances
         */
        class ExtensionFactory
        {
        public:
            // Type alias for the extension creator function
            using ExtensionCreatorFunc = std::function<std::shared_ptr<ExtensionBase>()>;

            /**
             * @brief Get the singleton instance of the ExtensionFactory
             * @return ExtensionFactory& The singleton instance
             */
            static ExtensionFactory &instance();

            /**
             * @brief Register a message extension type with the factory
             * @param ext_name The name of the extension
             * @param creator The creator function for the extension
             */
            static void registerMessageExtension(const std::string &ext_name, ExtensionCreatorFunc creator);

            /**
             * @brief Register a constraint extension type with the factory
             * @param ext_name The name of the extension
             * @param creator The creator function for the extension
             */
            static void registerConstraintExtension(const std::string &ext_name, ExtensionCreatorFunc creator);

            /**
             * @brief Create a message extension instance by name
             * @param ext_name The name of the extension
             * @return std::shared_ptr<ExtensionBase> The created extension instance, or nullptr if not found
             */
            static std::shared_ptr<ExtensionBase> createMessageExtension(const std::string &ext_name);

            /**
             * @brief Create a constraint extension instance by name
             * @param ext_name The name of the extension
             * @return std::shared_ptr<ExtensionBase> The created extension instance, or nullptr if not found
             */
            static std::shared_ptr<ExtensionBase> createConstraintExtension(const std::string &ext_name);

            /**
             * @brief Initialize and register all built-in extensions
             */
            static void initializeExtensions();

        private:
            ExtensionFactory() = default;

            std::unordered_map<std::string, ExtensionCreatorFunc> m_message_extension_creators;
            std::unordered_map<std::string, ExtensionCreatorFunc> m_constraint_extension_creators;
        };
    } // namespace libssha
} // namespace nglab
