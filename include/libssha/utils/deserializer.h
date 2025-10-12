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
#include <cstdint>
#include <string>
#include <libssha/utils/secure_vector.h>

namespace nglab
{
    namespace libssha
    {
        /**
         * @class Deserializer
         * @brief Utility class for deserializing binary data in SSH-like protocols.
         *
         * The Deserializer class provides methods to read various data types from a binary buffer,
         * such as big-endian integers, blobs, strings, and multi-precision integers (mpint).
         * It is designed to work with data formats commonly used in SSH and similar protocols.
         *
         * The class supports multiple constructors for different data sources, including raw pointers,
         * std::string, std::vector<uint8_t>, and secure_vector<uint8_t>. The data passed to the
         * Deserializer must remain valid for the lifetime of the Deserializer object.
         *
         * Example usage:
         * @code
         * // Example 1: Using std::vector<uint8_t>
         * std::vector<uint8_t> buffer = {0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
         * libssha::Deserializer deserializer(buffer);
         * std::string str = deserializer.readString(); // str == "hello"
         *
         * // Example 2: Reading a big-endian 32-bit integer
         * std::vector<uint8_t> buffer = {0x00, 0x00, 0x01, 0x2C};
         * libssha::Deserializer deserializer(buffer);
         * uint32_t value = deserializer.readBE32(); // value == 300
         *
         * // Example 3: Reading a blob and a byte
         * std::vector<uint8_t> buffer = {0x00, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE, 0xEF};
         * libssha::Deserializer deserializer(buffer);
         * std::vector<uint8_t> blob = deserializer.readBlob(); // blob == {0xDE, 0xAD, 0xBE}
         * uint8_t byte = deserializer.readByte(); // byte == 0xEF
         * @endcode
         *
         * @note
         * - All read methods throw std::out_of_range if there is not enough data to read.
         * - The offset() and remaining() methods can be used to track the current position and remaining bytes.
         * - Use slice() and sliceSecure() to extract subranges of the data.
         *
         * Typical use cases include parsing SSH packets, cryptographic messages, or any protocol
         * that uses length-prefixed or big-endian encoded binary data.
         */
        class Deserializer
        {
        public:
            /**
             * @brief Construct a new Deserializer object
             * Make sure that data is available for entire life of the object.
             *
             * @param data Pointer to the binary data to be deserialized
             * @param length Length of the binary data
             */
            Deserializer(const unsigned char *data, size_t length);

            /**
             * @brief Construct a new Deserializer object
             *
             * Make sure that data is available for entire life of the object.
             *
             * @param data Pointer to the binary data to be deserialized
             */
            Deserializer(const std::string &data);

            /**
             * @brief Construct a new Deserializer object
             *
             * @param data Pointer to the binary data to be deserialized
             */
            Deserializer(const secure_vector<uint8_t> &data)
                : Deserializer(reinterpret_cast<const unsigned char *>(data.data()), data.size()) {}

            /**
             * @brief Construct a new Deserializer object
             *
             * @param data Pointer to the binary data to be deserialized
             */
            Deserializer(const std::vector<uint8_t> &data)
                : Deserializer(reinterpret_cast<const unsigned char *>(data.data()), data.size()) {}

            /**
             * @brief Read a big-endian 32-bit unsigned integer from the data
             * @return uint32_t The read integer
             * @throws std::out_of_range if there is no more data to read
             */
            uint32_t readBE32();

            /**
             * @brief Read a blob (length-prefixed string) from the data
             * @return std::string The read blob
             * @throws std::out_of_range if there is no more data to read
             */
            std::vector<uint8_t> readBlob();

            /**
             * @brief Discard a blob (length-prefixed string) from the data
             * @throws std::out_of_range if there is no more data to read
             */
            void discardBlob();

            /**
             * @brief Read a secure blob (length-prefixed string) from the data
             * @return secure_vector<uint8_t> The read secure blob
             * @throws std::out_of_range if there is no more data to read
             */
            secure_vector<uint8_t> readBlobSecure();

            /**
             * @brief Read a single byte from the data
             * @return uint8_t The read byte
             * @throws std::out_of_range if there is no more data to read
             */
            uint8_t readByte();

            /**
             * @brief Read a string from the data
             * @return std::string The read string
             * @throws std::out_of_range if there is no more data to read
             */
            std::string readString();

            /**
             * @brief Read a multi-precision integer (mpint) from the data
             *
             * This method reads an mpint as defined in the SSH protocol:
             * - The mpint is stored as a length-prefixed byte array.
             * - If the most significant bit of the first byte is set, a leading zero byte
             *   is added to indicate that the integer is positive.
             *
             * @return std::vector<uint8_t> The read mpint
             * @throws std::out_of_range if there is no more data to read
             */
            std::vector<uint8_t> readMPInt();

            /**
             * @brief Read a multi-precision integer (mpint) from the data into a secure vector
             *
             * This is the same as readMPInt but stores the result in a secure_vector.
             *
             * @return secure_vector<uint8_t> The read mpint
             * @throws std::out_of_range if there is no more data to read
             */
            secure_vector<uint8_t> readMPIntSecure();

            /**
             * @brief Get the current offset in the data
             * @return size_t The current offset
             */
            size_t offset() const { return m_offset; }

            /**
             * @brief Get the remaining bytes in the data
             * @return size_t The number of remaining bytes
             */
            size_t remaining() const { return m_length - m_offset; }

            /**
             * @brief Get a slice of the data from start to end (exclusive)
             * @param start The starting index of the slice
             * @param end The ending index of the slice (exclusive)
             * @return secure_vector<uint8_t> The sliced data
             * @throws std::out_of_range if start or end are out of bounds
             */
            std::vector<uint8_t> slice(size_t start, size_t end) const;

            /**
             * @brief Get a secure slice of the data from start to end (exclusive)
             * @param start The starting index of the slice
             * @param end The ending index of the slice (exclusive)
             * @return secure_vector<uint8_t> The sliced secure data
             * @throws std::out_of_range if start or end are out of bounds
             */
            secure_vector<uint8_t> sliceSecure(size_t start, size_t end) const;

            ~Deserializer();

        private:
            const unsigned char *m_data;
            size_t m_length;
            size_t m_offset;
        };
    }
}