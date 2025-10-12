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
#include <libssha/utils/deserializer.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/secure_vector.h>

namespace nglab
{
  namespace libssha
  {
    using std::string;

    /**
     * @brief Enum representing SSH agent message types.
     * 
     * These message types are defined in the SSH agent protocol
     * as per draft-ietf-sshm-ssh-agent section 6.1
     */
    enum MessageType : uint8_t
    {
      SSH_AGENTC_REQUEST_IDENTITIES = 11,
      SSH_AGENTC_SIGN_REQUEST = 13,
      SSH_AGENTC_ADD_IDENTITY = 17,
      SSH_AGENTC_REMOVE_IDENTITY = 18,
      SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19,
      SSH_AGENTC_LOCK = 22,
      SSH_AGENTC_UNLOCK = 23,
      SSH_AGENTC_ADD_IDENTITY_CONSTRAINED = 25,
      SSH_AGENTC_EXTENSION = 27,

      SSH_AGENT_FAILURE = 5,
      SSH_AGENT_SUCCESS = 6,
      SSH_AGENT_IDENTITIES_ANSWER = 12,
      SSH_AGENT_SIGN_RESPONSE = 14,

      SSH_AGENTC_ADD_SMARTCARD_KEY = 20,
      SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21,
      SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26,
      SSH_AGENT_EXTENSION_FAILURE = 28,
      SSH_AGENT_EXTENSION_RESPONSE = 29,

      // Deprecated message types
      SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9
    };

    /**
     * @brief Enum representing key constraints in SSH agent.
     * 
     * These constraints are used when adding keys to the agent
     * as per draft-ietf-sshm-ssh-agent section 6.2
     */
    enum KeyConstraint : uint8_t
    {
      SSH_AGENT_CONSTRAIN_LIFETIME = 1,
      SSH_AGENT_CONSTRAIN_CONFIRM = 2,
      SSH_AGENT_CONSTRAIN_EXTENSION = 255
    };

    /**
     * @brief Class representing a generic SSH agent message.
     */
    class Message
    {
    public:
      /**
       * Constructor for Message.
       *
       * This constructor initializes the message with the given raw data.
       * and extracts the message type from the first byte of the data.
       * Also, it validates that the data is not empty or malformed.
       * @param data The raw data of the message.
       */
      Message(const string &data);

      /**
       * Constructor for Message.
       *
       * This constructor initializes the message with the given raw data.
       * and extracts the message type from the first byte of the data.
       * Also, it validates that the data is not empty or malformed.
       * @param data Pointer to the raw data of the message.
       * @param length Length of the raw data.
       */
      Message(const uint8_t *data, size_t length);

      /**
       * Constructor for Message.
       *
       * This constructor initializes the message with the given type.
       * @param type The type of the message.
       */
      Message(uint8_t type);

      /**
       * Get the type of the message.
       */
      uint8_t type() const;

      /**
       * Get the name of the message type as in draft-ietf-sshm-ssh-agent
       */
      string typeName() const;

      /**
       * Serialize the message to a string.
       */
      virtual secure_vector<uint8_t> serialize() const;

      /**
       * Get the raw data of the message.
       */
      const uint8_t *data() const { return m_data; }

      /**
       * Get the length of the message data.
       */
      size_t length() const { return m_length; }

    protected:
      Message() = default;

      /**
       * Deserialize the message from a Deserializer object.
       * @param data The Deserializer object containing the message data.
       */
      virtual void deserialize(Deserializer &data);      
      /**
       * Serialize the message to a Serializer object.
       * @param s The Serializer object to write the message data to.
       */
      virtual void serialize(Serializer &s) const;

      uint8_t m_type;
      const uint8_t *m_data{nullptr};
      size_t m_length{0};
    };

    /**
     * @brief Class template representing a simple message with no additional data.
     * 
     * This class is used for messages that only consist of a type byte
     * and have no additional payload.
     * @tparam msg_type The type of the message.
     */
    template <uint8_t msg_type> class SimpleMessage : public Message
    {
    public:
      SimpleMessage() : Message(msg_type) {}
      SimpleMessage(const string &data) : Message(data) {}
      SimpleMessage(const uint8_t *data, size_t length) : Message(data, length) {}
    };

    /// @brief Type aliases for common simple messages
    typedef SimpleMessage<SSH_AGENT_FAILURE> FailureMessage;
    typedef SimpleMessage<SSH_AGENT_SUCCESS> SuccessMessage;
    typedef SimpleMessage<SSH_AGENTC_REQUEST_IDENTITIES> RequestIdentitiesMessage;
    typedef SimpleMessage<SSH_AGENTC_REMOVE_ALL_IDENTITIES> RemoveAllIdentitiesMessage;
    typedef SimpleMessage<SSH_AGENT_EXTENSION_FAILURE> ExtensionFailureMessage;

  } // namespace libssha
} // namespace nglab