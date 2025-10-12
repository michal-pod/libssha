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
#include <botan/ed25519.h>
#include <botan/ed448.h>
namespace nglab
{
    namespace libssha
    {
        namespace {
            constexpr const char ed25519_pub_type_name[] = "ssh-ed25519";
            constexpr const char ed448_pub_type_name[] = "ssh-ed448";
        }

        /**
         * @brief Public key class for EDDSA (Ed25519) keys
         */
        class ED25519Pub : public PubKey<ED25519Pub, ed25519_pub_type_name>
        {
        public:
            ED25519Pub(const std::vector<uint8_t> &blob);
            virtual bool verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const override;
            virtual size_t bits() const override;
            virtual string family() const override { return "ED25519"; }
        private:
            std::unique_ptr<Botan::Ed25519_PublicKey> m_pub_key;
        };

        /**
         * @brief Public key class for EDDSA (Ed448) keys
         */
        class ED448Pub : public PubKey<ED448Pub, ed448_pub_type_name>
        {
        public:
            ED448Pub(const std::vector<uint8_t> &blob);
            virtual bool verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const override;
            virtual size_t bits() const override;
            virtual string family() const override { return "ED448"; }
        private:
            std::unique_ptr<Botan::Ed448_PublicKey> m_pub_key;
        };
    } // namespace libssha
} // namespace nglab