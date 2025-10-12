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
#include <libssha/utils/secure_vector.h>
#include <string>
#include <chrono>
#include <vector>
#include <libssha/key/key-factory.h>
#include <libssha/extensions/openssh-restrict-destination.h>
#include <libssha/agent/match-info.h>
#include <libssha/key/pub-key.h>
namespace nglab
{
    namespace libssha
    {
        class OpenSSHSDestinationConstraint;
        class Session;
        class KeyBase
        {
        public:
            virtual ~KeyBase() = default;

            /**
             * @brief Get the public key blob
             * @return std::vector<uint8_t> The public key blob
             */
            virtual std::vector<uint8_t> pubBlob(){
                if (m_pubkey)
                    return m_pubkey->blob();
                return {};
            }

            /**
             * @brief Get the key comment
             * @return std::string The key comment
             */
            std::string comment() const { return m_comment; }

            /**
             * @brief Set the key comment
             * @param comment The new key comment
             */
            void setComment(const std::string &comment) { m_comment = comment; }

            /**
             * @brief Get the key fingerprint (e.g., SHA256 base64-encoded)
             * @return std::string The key fingerprint
             */
            virtual std::string fingerprint(PubKeyBase::FingerprintFormat type = PubKeyBase::FingerprintFormat::Sha256Base64) const{
                if (m_pubkey)
                    return m_pubkey->fingerprint(type);
                return "NULL";
            }

            /**
             * @brief Sign the given data with the private key
             * @param data The data to be signed
             * @return std::string The signature
             */
            virtual std::vector<uint8_t> sign(const std::vector<uint8_t> &data, uint32_t flags) const = 0;

            /**
             * @brief Get the remaining lifetime of the key in seconds
             * @return int The remaining lifetime in seconds, or -1 if the key does not expire
             */
            int expireInSeconds() const
            {
                if(m_lifetime_seconds == 0)
                    return -1;
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_added_time).count();
                return static_cast<int>(m_lifetime_seconds - elapsed);                
            }

            /**
             * @brief Check if the key has expired
             * @return true if the key has expired, false otherwise
             */
            bool expired() const
            {
                if (m_lifetime_seconds == 0)
                    return false;
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_added_time).count();
                return elapsed >= m_lifetime_seconds;
            }

            /**
             * @brief Set the lifetime of the key in seconds
             * @param lifetime_seconds The lifetime in seconds
             */
            void setLifetime(uint32_t lifetime_seconds)
            {
                m_lifetime_seconds = lifetime_seconds;
                m_added_time = std::chrono::steady_clock::now();
            }

            /**
             * @brief Check if confirmation is required for using the key
             * @return true if confirmation is required, false otherwise
             */
            bool confirmRequired() const
            {
                return m_confirm_required;
            }

            /**
             * @brief Set whether confirmation is required for using the key
             * @param confirm_required true to require confirmation, false otherwise
             */
            void setConfirmRequired(bool confirm_required)
            {
                m_confirm_required = confirm_required;
            }

            /**
             * @brief Get the OpenSSH destination constraints associated with the key
             * @return const std::vector<OpenSSHSDestinationConstraint>& The destination constraints
             */
            const std::vector<OpenSSHSDestinationConstraint> &destConstraints() const
            {
                return m_dest_constraints;
            }

            /**
             * @brief Set the OpenSSH destination constraints associated with the key
             * @param constraints The destination constraints
             */
            void setDestConstraints(const std::vector<OpenSSHSDestinationConstraint> &constraints)
            {
                m_dest_constraints = constraints;
            }

            /**
             * @brief Check if the key has any OpenSSH destination constraints
             * @return true if there are destination constraints, false otherwise
             */
            bool hasDestConstraints() const
            {
                return !m_dest_constraints.empty();
            }

            /**
             * @brief Check if the key is permitted by the given constraints
             * @param from_key The source key
             * @param to_key The destination key
             * @param user The user name
             * @return true if the key is permitted, false otherwise
             */
            bool permittedByConstraints(const std::vector<uint8_t> &from_key,
                                        const std::vector<uint8_t> &to_key,
                                        const std::string &user,
                                        MatchInfoOpt mi = std::nullopt) const;

            /**
             * @brief Check if the key is permitted in the given session for the specified user
             * @param session The session to check against
             * @param user The user name
             * @return true if the key is permitted, false otherwise
             */
            bool permitted(const Session &session, std::string user, MatchInfoOpt mi = std::nullopt) const;

            /**
             * @brief Get the public key object
             * @return const PubKeyBase& The public key object
             */
            PubKeyBase& pubKey() const { return *m_pubkey; }

            /**
             * @brief Lock the private key with the given password
             * @param password The password to lock the key
             */
            virtual void lock(secure_vector<uint8_t> &password) = 0;

            /**
             * @brief Unlock the private key with the given password
             * @param password The password to unlock the key
             * @return true if the key was successfully unlocked, false otherwise
             */
            virtual bool unlock(secure_vector<uint8_t> &password) = 0;

            /**
             * @brief Get the key type string
             * @return std::string The key type
             */
            virtual std::string type() const = 0;

        protected:
            std::string m_comment;
            std::unique_ptr<PubKeyBase> m_pubkey;

            std::chrono::steady_clock::time_point m_added_time;
            uint32_t m_lifetime_seconds = 0;
            std::vector<OpenSSHSDestinationConstraint> m_dest_constraints;
            bool m_confirm_required = false;
        };

        /**
         * @brief Helper template class for registering key types
         */
        template <typename T, const char *type_name>
        class Key : public KeyBase
        {
        public:
            Key() {};
            virtual ~Key() = default;
            /**
             * @brief Register the key type with the factory
             */
            static void registerType()
            {
                KeyFactory::instance().registerKeyType(
                    type_name,
                    [](const secure_vector<uint8_t> &blob, const std::string &comment) -> std::shared_ptr<KeyBase>
                    {
                        return std::make_shared<T>(blob, comment);
                    },
                    [](const secure_vector<uint8_t> &blob) -> std::vector<uint8_t>
                    {
                        return T::extractPub(blob);
                    },
                    [](Deserializer &d)
                    {
                        return T::skipBlob(d);
                    });
            }

            /**
             * @brief Get the type name of the key
             * @return std::string The type name
             */
            static std::string typeName()
            {
                return type_name;
            }

            virtual std::string type() const override
            {
                return type_name;
            }
        };
    } // namespace libssha
} // namespace nglab