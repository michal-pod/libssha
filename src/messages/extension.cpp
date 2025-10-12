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
#include <libssha/messages/extension.h>

namespace nglab
{
    namespace libssha
    {

        ExtensionMessage::ExtensionMessage()
            : Message(SSH_AGENTC_EXTENSION),
            LogEnabler("ExtensionMessage"),
            m_extension_name(""),
            m_extension(nullptr)
        {
        }

        ExtensionMessage::ExtensionMessage(const Message &msg)
            : Message(msg),
            LogEnabler("ExtensionMessage"),
            m_extension_name(""),
            m_extension(nullptr)
        {
            if (msg.type() != SSH_AGENTC_EXTENSION)
            {
                log.error("ExtensionMessage: incorrect message type: {}", msg.type());
                throw std::runtime_error("ExtensionMessage: incorrect message type");
            }

            if (msg.data() == nullptr || msg.length() == 0)
            {
                log.error("ExtensionMessage: no data");
                throw std::runtime_error("ExtensionMessage: no data");
            }

            Deserializer d(msg.data(), msg.length());
            deserialize(d);
        }

        secure_vector<uint8_t> ExtensionMessage::serialize() const
        {
            Serializer s;
            Message::serialize(s);
            s.writeString(m_extension_name);
            if (m_extension)
            {
                m_extension->serialize(s);
            }
            return s.dataSecure();
        }

        std::string ExtensionMessage::extensionName() const
        {
            return m_extension_name;
        }

        std::shared_ptr<ExtensionBase> ExtensionMessage::extension() const
        {
            return m_extension;
        }

        void ExtensionMessage::setExtension(std::string name, std::shared_ptr<ExtensionBase> ext)
        {
            m_extension_name = name;
            m_extension = ext;
        }

        void ExtensionMessage::deserialize(Deserializer &s)
        {
            Message::deserialize(s);
            m_extension_name = s.readString();
            m_extension = ExtensionFactory::createMessageExtension(m_extension_name);
            if (m_extension)
            {
                m_extension->deserialize(s);
            }
        }
    } // namespace libssha
} // namespace nglab