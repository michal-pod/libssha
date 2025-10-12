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
#include <libssha/providers/botan/botan-lock-provider.h>
#include <string>
#include <botan/argon2fmt.h>
#include <botan/auto_rng.h>
namespace nglab
{
    namespace libssha
    {
        void BotanLockProvider::lock(secure_vector<uint8_t> passphrase)
        {
            // Implement locking logic here using Botan if needed
            // For now, this is a stub implementation
            Botan::AutoSeeded_RNG rng;
            m_hash = Botan::argon2_generate_pwhash(reinterpret_cast<const char*>(passphrase.data()), passphrase.size(),rng, 2, 1 << 16, 3);
                                                  
        }

        bool BotanLockProvider::verify(secure_vector<uint8_t> passphrase)
        {
            // Implement unlocking logic here using Botan if needed
            // For now, this is a stub implementation
            return Botan::argon2_check_pwhash(reinterpret_cast<const char*>(passphrase.data()), passphrase.size(), m_hash);           
        }


    } // namespace libssha
} // namespace nglab