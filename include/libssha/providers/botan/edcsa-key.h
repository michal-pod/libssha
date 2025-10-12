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
#include <string>
#include <vector>
#include <libssha/utils/secure_vector.h>
#include <botan/ecdsa.h>
#include <libssha/providers/botan/botan-lock.h>

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;


        /**
         * @brief ECDSA Key implementation
         */
        class ECDSAKey : public KeyBase, public BotanLock
        {
        public:
            ECDSAKey(const secure_vector<uint8_t> &blob, const std::string &comment, const std::string &type_name = "");
            static void skipBlob(Deserializer &d);
            static std::vector<uint8_t> extractPub(const secure_vector<uint8_t> &data);
            virtual std::string fingerprint() const;
            virtual std::vector<uint8_t> sign(const std::vector<uint8_t> &data, uint32_t flags) const;
            virtual std::vector<uint8_t> pubBlob() const  { return m_pub_blob; }

            void lock(secure_vector<uint8_t>& password) override;
            bool unlock(secure_vector<uint8_t>& password) override;

            virtual std::string type() const override { return m_type_name; }

            static void registerKeyType();
        private:
            string m_type_name;
            string m_curve_name;
            string m_botan_curve_name;
            string m_signature_algorithm;
            vector<uint8_t> m_pub_blob;
            std::unique_ptr<Botan::ECDSA_PrivateKey> m_priv_key;

            static constexpr const char* edcsa_sha2_nistp256_type_name = "ecdsa-sha2-nistp256";
            static constexpr const char* edcsa_sha2_nistp384_type_name = "ecdsa-sha2-nistp384";
            static constexpr const char* edcsa_sha2_nistp521_type_name = "ecdsa-sha2-nistp521";
        };



    }
}
