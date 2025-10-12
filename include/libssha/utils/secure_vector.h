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
#include <cstddef>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace nglab
{
    namespace libssha
    {
        /**
         * @brief A custom allocator that securely zeroes memory on deallocation
         *
         * This allocator can be used with STL containers to ensure that sensitive data
         * is cleared from memory when the container is destroyed or resized.
         * 
         * This allocator uses mlock/munlock on POSIX systems and VirtualLock/VirtualUnlock on Windows
         * to prevent sensitive data from being swapped to disk.
         */
        template <typename T>
        class SecureAllocator
        {
        public:
            using value_type = T;

            SecureAllocator() noexcept  = default;
            SecureAllocator(const SecureAllocator &) noexcept = default;
            SecureAllocator(SecureAllocator &&) noexcept = default;
            SecureAllocator &operator=(const SecureAllocator &) noexcept = default;
            SecureAllocator &operator=(SecureAllocator &&) noexcept = default;
            ~SecureAllocator() noexcept = default;

            template <typename U>
            explicit SecureAllocator(const SecureAllocator<U> &) noexcept {}

            T *allocate(std::size_t n)
            {
                if (n > std::size_t(-1) / sizeof(T))
                    throw std::bad_alloc();
                T *p = static_cast<T *>(::operator new(n * sizeof(T)));
#ifdef _WIN32
                VirtualLock(static_cast<const LPVOID>(p), n * sizeof(T));
#else
                mlock(static_cast<const void *>(p), n * sizeof(T));
#endif
                return p;
            }

            void deallocate(T *p, std::size_t n) noexcept
            {
                if (p)
                {
                    volatile T *vp = p;
                    memset(const_cast<T *>(vp), 0x42, n * sizeof(T));
                    

                    #ifdef _WIN32
                    VirtualUnlock(static_cast<LPVOID>(const_cast<T*>(p)), n * sizeof(T));
                    #else
                    munlock(static_cast<const void *>(const_cast<T *>(vp)), n * sizeof(T));
                    #endif
                }
                ::operator delete(p);
            }
        };

        template <typename T, typename U>
        inline bool operator==(const SecureAllocator<T> &, const SecureAllocator<U> &) noexcept
        {
            return true;
        }

        template <typename T, typename U>
        inline bool operator!=(const SecureAllocator<T> &, const SecureAllocator<U> &) noexcept
        {
            return false;
        }

        template <typename T>
        using secure_vector = std::vector<T, SecureAllocator<T>>;
    } // namespace libssha
} // namespace nglab