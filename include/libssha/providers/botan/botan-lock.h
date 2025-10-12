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
#include <vector>
#include <cstdint>
#include <libssha/utils/secure_vector.h>
#include <memory>

namespace Botan
{
    class Private_Key;
}

namespace nglab
{
    namespace libssha
    {

        /**
         * @brief Class to handle locking and unlocking of Botan private key data in memory
         */
        class BotanLock
        {
        public:
            /**
             * @brief Protects the given Botan private key data using the provided password
             */
            void protectData(Botan::Private_Key const &key, const secure_vector<uint8_t> &password);
            
            /**
             * @brief Unprotects and retrieves the Botan private key data using the provided password
             */
            std::unique_ptr<Botan::Private_Key> unprotectData(const secure_vector<uint8_t> &password);

        private:
            std::vector<uint8_t> m_locked_data;
        };

    }

}