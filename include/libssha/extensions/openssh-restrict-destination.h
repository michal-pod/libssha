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
#include <libssha/extensions/extension.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <memory>
#include <string>
#include <libssha/utils/logger.h>
#include <libssha/agent/match-info.h>
namespace nglab
{
    namespace libssha
    {
        namespace
        {
            constexpr const char openssh_session_restrict_destination_ext_name[] = "restrict-destination-v00@openssh.com";
        }

        /**
         * @brief Represents a key in an OpenSSH hop descriptor
         */
        struct OpenSSHHopKey
        {
            std::vector<uint8_t> key;
            bool key_is_ca;
        };

        /**
         * @brief Represents a hop descriptor in OpenSSH restrict-destination extension
         */
        class OpenSSHHopDescriptor : public LogEnabler
        {
        public:
            // Construct from binary data
            OpenSSHHopDescriptor(std::vector<uint8_t> &data, std::string tag = std::string());
            // Construct from components
            OpenSSHHopDescriptor(const std::vector<OpenSSHHopKey> &keys = {}, std::string hostname = std::string(), std::string user = std::string());

            // Serialize this hop descriptor into a binary blob matching the wire format
            std::vector<uint8_t> serialize() const;

            // Getters
            const std::string &user() const { return m_user; }
            const std::string &hostname() const { return m_hostname; }
            const std::vector<OpenSSHHopKey> &keys() const { return m_keys; }

            // Check if the given key matches any key in this hop descriptor
            bool matchesKey(const std::vector<uint8_t> &key) const;

            // Get a string representation for displaying to user
            std::string toString() const;

        private:
            std::string m_user;
            std::string m_hostname;
            std::vector<OpenSSHHopKey> m_keys;
        };

        /**
         * @brief Represents a destination constraint in OpenSSH restrict-destination extension
         */
        class OpenSSHSDestinationConstraint : public LogEnabler
        {
        public:
            // Construct from binary data
            OpenSSHSDestinationConstraint(std::vector<uint8_t> &data);
            // Construct from components
            OpenSSHSDestinationConstraint(const OpenSSHHopDescriptor &from, const OpenSSHHopDescriptor &to);

            // Serialize this constraint into a binary blob matching the wire format
            std::vector<uint8_t> serialize() const;

            // Getters
            const OpenSSHHopDescriptor &fromHop() const { return m_from_hop; }
            const OpenSSHHopDescriptor &toHop() const { return m_to_hop; }

            // Setters
            void setFromHop(const std::vector<OpenSSHHopKey> &keys = {}, const std::string hostname = std::string(), const std::string user = std::string())
            {
                m_from_hop = OpenSSHHopDescriptor(keys, hostname, user);
            }
            void setToHop(const std::vector<OpenSSHHopKey> &keys = {}, const std::string hostname = std::string(), const std::string user = std::string())
            {
                m_to_hop = OpenSSHHopDescriptor(keys, hostname, user);
            }


            // permitted_by_dest_constraints
            bool matches(const std::vector<uint8_t> &from_key,
                         const std::vector<uint8_t> &to_key,
                         const std::string &user,
                         MatchInfoOpt mi = std::nullopt) const;

        private:
            OpenSSHHopDescriptor m_from_hop;
            OpenSSHHopDescriptor m_to_hop;
        };

        /**
         * @brief Represents the OpenSSH restrict-destination extension
         */
        class OpenSSHSRestrictDestination : public Extension<OpenSSHSRestrictDestination,
                                                             openssh_session_restrict_destination_ext_name,
                                                             ExtensionType::ConstraintExtension>,
                                            public LogEnabler
        {
        public:
            OpenSSHSRestrictDestination();

            virtual void serialize(Serializer &s) const override;
            virtual void deserialize(Deserializer &d) override;

            const std::vector<OpenSSHSDestinationConstraint> &constraints() const { return m_constraints; }

        private:
            std::vector<OpenSSHSDestinationConstraint> m_constraints;
        };
    }
}