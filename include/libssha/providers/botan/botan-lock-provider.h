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
#include <libssha/key/lock-provider.h>
#include <libssha/utils/secure_vector.h>
#include <string>
namespace nglab
{
    namespace libssha
    {
        class BotanLockProvider : public LockProvider
        {
        public:
            void lock(secure_vector<uint8_t> passphrase) override;
            bool verify(secure_vector<uint8_t> passphrase) override;
        private:
            std::string m_hash;

        };
    }
}
