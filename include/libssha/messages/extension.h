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
#include "message.h"
#include <string>
#include <vector>
#include <libssha/utils/secure_vector.h>
#include <libssha/utils/logger.h>
#include <libssha/extensions/extension.h>

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;

        /**
         * @brief Class representing an Extension Message.
         * @brief Class representing an Extension Message.
         * 
         * This class is used to handle messages that contain extensions
         * as defined in the SSH agent protocol (draft-ietf-sshm-ssh-agent).
         */
        class ExtensionMessage : public Message, public LogEnabler
        {
        public:
        /**
         * @brief Construct a new ExtensionMessage object
         */
            ExtensionMessage();
            /**
             * @brief Construct a new ExtensionMessage object from a Message
             * @param msg The Message object to construct from
             */
            ExtensionMessage(const Message &msg);

            /**
             * @brief Serialize the ExtensionMessage to a string.
             * @return A string containing the serialized message.
             */
            virtual secure_vector<uint8_t> serialize() const override;

            /**
             * @brief Get the name of the extension
             * @return The extension name
             */
            std::string extensionName() const;

            /**
             * @brief Get the ExtensionBase object
             * @return The ExtensionBase object
             */
            std::shared_ptr<ExtensionBase> extension() const;

            /**
             * @brief Set the ExtensionBase object
             * @param ext The ExtensionBase object to set
             */
            void setExtension(std::string, std::shared_ptr<ExtensionBase> ext);


        private:
            virtual void deserialize(Deserializer &s) override;

            std::string m_extension_name;
            std::shared_ptr<ExtensionBase> m_extension;
        };
    }
}
