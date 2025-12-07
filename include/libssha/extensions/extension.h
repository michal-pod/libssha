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
#include <libssha/extensions/extension-factory.h>
namespace nglab
{
    namespace libssha
    {

        /**
         * @brief Enum representing the type of extension
         * MessageExtension:
         * An extension that applies to messages as in the SSH agent protocol described in
         * draft-ietf-sshm-ssh-agent section 3.8.
         *
         * In this library I support only extension session-bind@openssh.com but this mechanism for
         * extension make easy to add new extensions in the future.
         *
         * ConstraintExtension:
         * An extension that applies to constraints
         *
         * This extension type is for key constraints extensions as described in
         * draft-ietf-sshm-ssh-agent section 3.2.7.
         */
        enum class ExtensionType
        {
            MessageExtension,
            ConstraintExtension,
        };

        class Deserializer;
        class Serializer;
        /**
         * @brief Base class for all extensions
         */
        class ExtensionBase
        {
        public:
            /**
             * @brief Deserialize the extension data from the deserializer
             * @param d The deserializer to read from
             */
            virtual void deserialize(Deserializer &d) = 0;

            /**
             * @brief Serialize the extension data to the serializer
             * @param s The serializer to write to
             */
            virtual void serialize(Serializer &s) const = 0;
        };

        /**
         * @brief Helper template class for registering extensions
         * @tparam T The extension class
         * @tparam ext_name The name of the extension
         * @tparam ext_type The type of the extension (MessageExtension or ConstraintExtension)
         */
        template <typename T, const char *ext_name, ExtensionType ext_type>
        class Extension : public ExtensionBase
        {
        public:
            virtual ~Extension() = default;
            /**
             * @brief Register the extension type with the factory
             */
            static void registerType()
            {
                if constexpr(ext_type == ExtensionType::MessageExtension)
                {
                    ExtensionFactory::instance().registerMessageExtension(
                        ext_name,
                        []() -> std::shared_ptr<ExtensionBase>
                        {
                            return std::make_shared<T>();
                        });
                }
                else if constexpr(ext_type == ExtensionType::ConstraintExtension)
                {
                    ExtensionFactory::instance().registerConstraintExtension(
                        ext_name,
                        []() -> std::shared_ptr<ExtensionBase>
                        {
                            return std::make_shared<T>();
                        });
                }
            }
        };

    }
}