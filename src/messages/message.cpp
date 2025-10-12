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
#include <libssha/messages/message.h>
#include <libssha/utils/serializer.h>
#include <stdexcept>
#include <unordered_map>

namespace nglab
{
  namespace libssha
  {

    Message::Message(const string &data)
    {
      Deserializer d(data);
      deserialize(d);
    }

    Message::Message(const uint8_t *data, size_t length) : m_type(0), m_data(data), m_length(length)
    {
      Deserializer d(data, length);
      deserialize(d);
    }

    Message::Message(uint8_t type) : m_type(type) {}


    void Message::deserialize(Deserializer &data)
    {
      data.readBE32(); // Read and discard length
      m_type = data.readByte();
    }

    secure_vector<uint8_t> Message::serialize() const
    {
      Serializer s;
      serialize(s);
      return s.dataSecure();
    }

    void Message::serialize(Serializer &s) const
    {
      s.writeBE32(1); // Placeholder for length
      s.writeByte(m_type);
    }

    uint8_t Message::type() const
    {
      return m_type;
    }
    
    std::string Message::typeName() const
    {
      // Mapping according to draft-ietf-sshm-ssh-agent section 6.1
      switch (m_type) {
        case SSH_AGENTC_REQUEST_IDENTITIES: return "SSH_AGENTC_REQUEST_IDENTITIES";
        case SSH_AGENTC_SIGN_REQUEST: return "SSH_AGENTC_SIGN_REQUEST";
        case SSH_AGENTC_ADD_IDENTITY: return "SSH_AGENTC_ADD_IDENTITY";
        case SSH_AGENTC_REMOVE_IDENTITY: return "SSH_AGENTC_REMOVE_IDENTITY";
        case SSH_AGENTC_REMOVE_ALL_IDENTITIES: return "SSH_AGENTC_REMOVE_ALL_IDENTITIES";
        case SSH_AGENTC_ADD_SMARTCARD_KEY: return "SSH_AGENTC_ADD_SMARTCARD_KEY";
        case SSH_AGENTC_REMOVE_SMARTCARD_KEY: return "SSH_AGENTC_REMOVE_SMARTCARD_KEY";
        case SSH_AGENTC_LOCK: return "SSH_AGENTC_LOCK";
        case SSH_AGENTC_UNLOCK: return "SSH_AGENTC_UNLOCK";
        case SSH_AGENTC_ADD_IDENTITY_CONSTRAINED: return "SSH_AGENTC_ADD_ID_CONSTRAINED";
        case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: return "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED";
        case SSH_AGENTC_EXTENSION: return "SSH_AGENTC_EXTENSION";
        case SSH_AGENT_FAILURE:  return "SSH_AGENT_FAILURE";
        case SSH_AGENT_SUCCESS:  return "SSH_AGENT_SUCCESS";
        case SSH_AGENT_IDENTITIES_ANSWER: return "SSH_AGENT_IDENTITIES_ANSWER";
        case SSH_AGENT_SIGN_RESPONSE: return "SSH_AGENT_SIGN_RESPONSE";
        case SSH_AGENT_EXTENSION_FAILURE: return "SSH_AGENT_EXTENSION_FAILURE";
        case SSH_AGENT_EXTENSION_RESPONSE: return "SSH_AGENT_EXTENSION_RESPONSE";
        default: return "UNKNOWN";
      }
    }

  } // namespace libssha
} // namespace nglab
