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
#include <vector>
#include <utility>
#include <libssha/utils/secure_vector.h>
#include "message.h"

namespace nglab
{
    namespace libssha
    {
        using std::pair;
        using std::string;
        using std::vector;

        /**
         * @brief Class representing an Identity (key blob and comment).
         */
        class Identity
        {
        public:
            /**
             * @brief Construct a new Identity object
             * @param blob The key blob
             * @param comment The key comment
             */
            Identity(const vector<uint8_t> &blob, const string &comment)
                : m_blob(blob), m_comment(comment) {}

            /**
             * @brief Get the key blob
             * @return const vector<uint8_t>& The key blob
             */
            const vector<uint8_t> &blob() const { return m_blob; }

            /**
             * @brief Get the key comment
             * @return const string& The key comment
             */
            const string &comment() const { return m_comment; }

        private:
            vector<uint8_t> m_blob;
            string m_comment;
        };

        /**
         * @brief Class representing an Identities Answer Message.
         */
        class IdentitiesAnswerMessage : public Message
        {
        public:
        /**
         * @brief Construct a new Identities Answer Message object
         */
            IdentitiesAnswerMessage();
            /**
             * @brief Construct a new Identities Answer Message object from a generic Message
             * @param msg The generic Message object
             * @throws std::runtime_error if the message type is incorrect or data is missing
             */
            IdentitiesAnswerMessage(const Message &msg);

            /**
             * @brief Serialize the message to a binary format
             * @return secure_vector<uint8_t> The serialized message
             * @throws std::runtime_error if the message type is incorrect
             */
            virtual secure_vector<uint8_t> serialize() const override;

            /**
             * @brief Get the identities
             * @return const vector<Identity>& The identities
             */
            const vector<Identity> &identities() const { return m_identities; }

            /**
             * @brief Add an identity
             * @param identity The identity blob
             * @param comment The identity comment
             */
            void addIdentity(const vector<uint8_t> &identity, const string &comment) { m_identities.emplace_back(identity, comment); }

        private:
            virtual void deserialize(Deserializer &s) override;

            vector<Identity> m_identities;
        };
    }
}