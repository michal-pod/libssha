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
#include <libssha/key/key-factory.h>

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;

        class PubKeyBase
        {
        public:
            enum FingerprintFormat
            {                
                Sha256Base64,
                Sha256Hex
            };
            /**
             * @brief Construct a new Pub Key Base object
             * @param blob The public key blob
             */
            PubKeyBase(const vector<uint8_t> &blob) : m_pub_blob(blob) {}

            virtual ~PubKeyBase() = default;

            /**
             * @brief Get SHA256 digest of the public key blob encoded in base64
             * @return string The fingerprint string
             */
            virtual string fingerprint(FingerprintFormat format = Sha256Base64) const;

            /**
             * @brief Get visual host key representation
             * @return vector<string> The visual host key lines
             */
            virtual std::vector<string> visualHostKey();

            /**
             * @brief Get the auth key line representation
             * @return std::string The auth key line
             */
            virtual std::string authKeyLine(std::string comment);

            /**
             * @brief Verify the signature for the given data
             * @param data The data to verify
             * @param signature The signature to verify
             * @return true if the signature is valid, false otherwise
             */
            virtual bool verify(const vector<uint8_t> &data, const vector<uint8_t> &signature) const = 0;

            /**
             * @brief Get the number of bits in the public key
             * @return size_t The number of bits
             */
            virtual size_t bits() const = 0;

            /**
             * @brief Get the key family (e.g., "ED25519", "RSA", etc.)
             * @return string The key family
             */
            virtual string family() const = 0;

            /**
             * @brief Get the type name of the public key
             * @return string The type name
             */
            virtual string type() const { return m_type; }

            /**
             * @brief Get the public key blob
             * @return const vector<uint8_t>& The public key blob
             */
            const vector<uint8_t>& blob() const { return m_pub_blob; }

        protected:
            std::string m_type;

        private:
            vector<uint8_t> pubKeyDigest() const;
            vector<uint8_t> m_pub_blob;
        };

        /**
         * @brief Helper template class for registering public key types
         */
        template <typename T, const char *type_name>
        class PubKey : public PubKeyBase
        {
        public:
            PubKey(const vector<uint8_t> &blob) : PubKeyBase(blob) {}
            ~PubKey() = default;
            static void registerType()
            {
                KeyFactory::instance().registerPubKeyType(
                    type_name,
                    [](const vector<uint8_t> &blob) -> std::shared_ptr<PubKeyBase>
                    {
                        return std::make_shared<T>(blob);
                    });
            }

            /**
             * @brief Get the type name of the public key
             * @return std::string The type name
             */
            static string typeName()
            {
                return type_name;
            }
        };
    }
}