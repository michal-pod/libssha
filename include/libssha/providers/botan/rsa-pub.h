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
#include <libssha/key/pub-key.h>
#include <botan/rsa.h>

namespace nglab
{
    namespace libssha
    {
        namespace
        {
            constexpr const char rsa_pub_type_name[] = "ssh-rsa";

        }

        /**
         * @brief Class representing an RSA public key
         */
        class RSAPub : public PubKey<RSAPub, rsa_pub_type_name>                      
        {
        public:
            RSAPub(const std::vector<uint8_t> &blob);
            virtual bool verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const override;
            virtual size_t bits() const override;
            virtual string family() const override { return "RSA"; }

        private:
            std::unique_ptr<Botan::RSA_PublicKey> m_pub_key;
        };
    } // namespace libssha
} // namespace nglab