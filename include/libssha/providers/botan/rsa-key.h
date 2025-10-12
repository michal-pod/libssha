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
#include <libssha/utils/secure_vector.h>
#include <botan/rsa.h>
#include <string>
#include <vector>
#include <libssha/providers/botan/botan-lock.h>

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;

        namespace {
            constexpr const char rsa_type_name[] = "ssh-rsa";
        }

        /**
         * RSA Key implementation
         */
        class RsaKey : public Key<RsaKey, rsa_type_name>, public BotanLock
        {
        public:
            RsaKey(const secure_vector<uint8_t> &blob,
                       const std::string &comment = "");            

            virtual std::vector<uint8_t> sign(const std::vector<uint8_t> &data, uint32_t flags) const override;
            static std::vector<uint8_t> extractPub(const secure_vector<uint8_t> &data);
            static void skipBlob(Deserializer &d);
            // Implement lock/unlock
            void lock(secure_vector<uint8_t>& password) override;
            bool unlock(secure_vector<uint8_t>& password) override;
        private:
            std::unique_ptr<Botan::RSA_PrivateKey> m_priv_key;
            vector<uint8_t> m_pub_blob;


        };
    }
}