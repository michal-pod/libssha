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
#include <libssha/messages/add-identity.h>
#include <stdexcept>
#include <libssha/key/key.h>
#include <libssha/key/key-factory.h>
#include <libssha/extensions/extension-factory.h>
#include <libssha/extensions/extension.h>
namespace nglab
{
    namespace libssha
    {
        AddIdentityMessage::AddIdentityMessage()
            : Message(SSH_AGENTC_ADD_IDENTITY), m_confirm_required(false), m_lifetime(0), LogEnabler("AddIdentityMessage")
        {
            if(m_confirm_required || m_lifetime > 0) {
                m_type = SSH_AGENTC_ADD_IDENTITY_CONSTRAINED;
            }
        }

        AddIdentityMessage::AddIdentityMessage(const Message& msg)
            : Message(), LogEnabler("AddIdentityMessage")
        {
            if (msg.type() != SSH_AGENTC_ADD_IDENTITY && msg.type() != SSH_AGENTC_ADD_IDENTITY_CONSTRAINED)
            {
                throw std::runtime_error("AddIdentityMessage: incorrect message type");
            }

            if(msg.data() == nullptr || msg.length() == 0) {
                throw std::runtime_error("AddIdentityMessage: no data");
            }

            Deserializer d(msg.data(), msg.length());
            deserialize(d);
        }



        secure_vector<uint8_t> AddIdentityMessage::serialize() const
        {
            Serializer s;
            Message::serialize(s);
            s.writeString(m_key_type);
            s.writeRaw(m_key_blob);
            s.writeString(m_key_comment);
            if (m_type == SSH_AGENTC_ADD_IDENTITY_CONSTRAINED)
            {
                if (m_confirm_required)
                {
                    s.writeByte(SSH_AGENT_CONSTRAIN_CONFIRM);
                }
                if (m_lifetime > 0)
                {
                    s.writeByte(SSH_AGENT_CONSTRAIN_LIFETIME);
                    s.writeBE32(m_lifetime);
                }
            }
            s.finalize();
            return s.dataSecure();
        }

        void AddIdentityMessage::deserialize(Deserializer &d)
        {
            Message::deserialize(d);
            if (m_type != SSH_AGENTC_ADD_IDENTITY && m_type != SSH_AGENTC_ADD_IDENTITY_CONSTRAINED)
            {
                throw std::runtime_error("AddIdentityMessage: incorrect message type");
            }
            m_key_type = d.readString();
            size_t start = d.offset();
            KeyFactory::skipKeyBlob(m_key_type, d);
            
            size_t end = d.offset();
            m_key_blob = d.sliceSecure(start, end);
            m_confirm_required = false;
            m_lifetime = 0;
            m_key_comment = d.readString();
            log.vdebug("key_type=%s, comment=%s", m_key_type.c_str(), m_key_comment.c_str());

            if (m_type == SSH_AGENTC_ADD_IDENTITY_CONSTRAINED)
            {
                // constraints
                while (d.remaining() > 0)
                {
                    uint8_t constr = d.readByte();
                    switch (constr)
                    {
                    case SSH_AGENT_CONSTRAIN_CONFIRM: // confirm
                        log.debug("has confirm constraint");
                        m_confirm_required = true;
                        break;
                    case SSH_AGENT_CONSTRAIN_LIFETIME: // lifetime
                    {
                        m_lifetime = d.readBE32();
                        log.debug("has lifetime: %u", m_lifetime);
                        break;
                    }
                    case SSH_AGENT_CONSTRAIN_EXTENSION:
                    {
                        std::string ext_type = d.readString();
                        log.debug("has extension: type=%s", ext_type.c_str());
                        m_extension = ExtensionFactory::instance().createConstraintExtension(ext_type);
                        if (!m_extension) {
                            throw std::runtime_error("AddIdentityMessage: unknown constraint extension " + ext_type);
                        }
                        m_extension->deserialize(d);
                        break;
                    }
                    default:
                        throw std::runtime_error("AddIdentityMessage: unknown constraint type " + std::to_string(constr));
                    }
                }
            }
        }

    } // namespace libssha
} // namespace nglab
