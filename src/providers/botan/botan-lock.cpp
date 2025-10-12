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
#include <libssha/providers/botan/botan-lock.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
namespace nglab
{
    namespace libssha
    {

        void BotanLock::protectData(Botan::Private_Key const &key, const secure_vector<uint8_t> &password)
        {
            Botan::AutoSeeded_RNG rng;

            m_locked_data.clear();
            m_locked_data = Botan::PKCS8::BER_encode(
                key,
                rng,
                std::string_view(reinterpret_cast<const char *>(password.data()), password.size()),
                std::chrono::milliseconds(200));
        }

        std::unique_ptr<Botan::Private_Key> BotanLock::unprotectData(const secure_vector<uint8_t> &password)
        {
            return Botan::PKCS8::load_key(
                m_locked_data,
                std::string_view(reinterpret_cast<const char *>(password.data()), password.size()));
        }

    }
}