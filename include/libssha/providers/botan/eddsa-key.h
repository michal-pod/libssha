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
#include <libssha/key/key.h>
#include <botan/ed25519.h>
#include <botan/ed448.h>
#include <libssha/utils/secure_vector.h>
#include <string>
#include <vector>
#include <libssha/providers/botan/botan-lock.h>

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;
        namespace
        {
            constexpr const char ed25519_type_name[] = "ssh-ed25519";
            constexpr const char ed448_type_name[] = "ssh-ed448";
        }

        /**
         * Common base class for EDDSA keys
         */
        class EDDSABase
        {
        public:
            static void skipBlob(Deserializer &d);
            static std::vector<uint8_t> extractPub(const secure_vector<uint8_t> &data, string type_name);
            virtual std::string fingerprint() const;

        protected:
            vector<uint8_t> m_pub_blob;
        };

        /**
         * @brief Ed25519 private key class
         */
        class Ed25519Key : public EDDSABase, public Key<Ed25519Key, ed25519_type_name>, public BotanLock
        {
        public:
            Ed25519Key(const secure_vector<uint8_t> &blob,
                       const std::string &comment = "");

            virtual std::vector<uint8_t> sign(const std::vector<uint8_t> &data, uint32_t flags) const override;
            static std::vector<uint8_t> extractPub(const secure_vector<uint8_t> &data)
            {
                return EDDSABase::extractPub(data, Ed25519Key::typeName());
            }
            static void skipBlob(Deserializer &d)
            {
                EDDSABase::skipBlob(d);
            }
            void lock(secure_vector<uint8_t>& password) override;
            bool unlock(secure_vector<uint8_t>& password) override;

        private:
            std::unique_ptr<Botan::Ed25519_PrivateKey> m_priv_key;
            vector<uint8_t> m_pub_blob;
        };

        /**
         * @brief Ed448 private key class
         */
        class Ed448Key : public EDDSABase, public Key<Ed448Key, ed448_type_name>, public BotanLock
        {
        public:
            Ed448Key(const secure_vector<uint8_t> &blob,
                       const std::string &comment = "");

            virtual std::vector<uint8_t> sign(const std::vector<uint8_t> &data, uint32_t flags) const override;
            static std::vector<uint8_t> extractPub(const secure_vector<uint8_t> &data)
            {
                return EDDSABase::extractPub(data, Ed448Key::typeName());
            }
            static void skipBlob(Deserializer &d)
            {
                EDDSABase::skipBlob(d);
            }
            void lock(secure_vector<uint8_t>& password) override;
            bool unlock(secure_vector<uint8_t>& password) override;

        private:
            std::unique_ptr<Botan::Ed448_PrivateKey> m_priv_key;
            vector<uint8_t> m_pub_blob;
        };

    } // namespace libssha
} // namespace nglab