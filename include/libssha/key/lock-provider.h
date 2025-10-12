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
#include <libssha/utils/secure_vector.h>
#include <cstdint>
namespace nglab
{
    namespace libssha
    {
        
        /**
         * @brief Interface for providing lock functionality for key management.
         *
         * This interface defines methods for locking and unlocking key management,
         * as well as checking the lock status.
         */
        class LockProvider
        {
        public:
            /**
             * @brief Virtual destructor for LockProvider.
             */
            virtual ~LockProvider() = default;

            /**
             * @brief Lock the key management.
             */
            virtual void lock(secure_vector<uint8_t> passphrase) = 0;

            /**
             * @brief Unlock the key management with the provided passphrase.
             * @param passphrase The passphrase to unlock the key management.
             */
            virtual bool verify(secure_vector<uint8_t> passphrase) = 0;
        };
    } // namespace libssha
} // namespace nglab