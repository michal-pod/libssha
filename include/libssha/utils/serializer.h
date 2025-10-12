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
         * @class Serializer
         * @brief Utility class for serializing various data types into a secure byte buffer.
         *
         * The Serializer class provides methods to serialize primitive types, strings, blobs,
         * and multi-precision integers (mpint) into a secure_vector<uint8_t> buffer. It is
         * designed for use in cryptographic and protocol implementations, such as SSH, where
         * precise control over data layout and security is required.
         *
         * Example usage:
         * @code
         * #include <libssha/utils/serializer.h>
         *
         * libssha::Serializer serializer;
         * serializer.writeBE32(0x12345678); // Write a 32-bit big-endian integer
         * serializer.writeString("hello");  // Write a string with length prefix
         * std::vector<uint8_t> blob = {0x01, 0x02, 0x03};
         * serializer.writeBlob(blob);       // Write a blob with length prefix
         *
         * // Write a multi-precision integer (mpint)
         * secure_vector<uint8_t> mpint = {0x00, 0xA1, 0xB2, 0xC3};
         * serializer.writeMPInt(mpint);
         *
         * serializer.finalize(); // Finalize serialization (e.g., write length prefix)
         *
         * // Retrieve the serialized data
         * secure_vector<uint8_t> data = serializer.data();
         * @endcode
         *
         * The Serializer ensures that all data is written in a format compatible with
         * SSH and similar protocols, including length prefixes and big-endian encoding
         * where required. It supports both standard and secure containers for sensitive data.
         */
        class Serializer
        {
        public:
            /**
             * @brief Construct a new Serializer object
             */
            Serializer() = default;
            /**
             * @brief Serialize a big-endian 32-bit unsigned integer to the data
             * @param value The integer to serialize
             */
            void writeBE32(uint32_t value, size_t at = -1);
            /**
             * @brief Serialize a string to the data
             * @param str The string to serialize
             */
            void writeString(const std::string &str);
            /**
             * @brief Serialize a blob (length-prefixed string) to the data
             * @param blob The blob to serialize
             */
            void writeBlob(const std::vector<uint8_t> &blob);
            /**
             * @brief Serialize a secure blob (length-prefixed string) to the data
             * @param blob The secure blob to serialize
             */
            void writeSecureBlob(const secure_vector<uint8_t> &blob);

            /**
             * @brief Serialize a single byte to the data
             * @param byte The byte to serialize
             */
            void writeByte(uint8_t byte, size_t at = -1);

            /**
             * @brief Write a multi-precision integer (mpint) to the data
             *
             * This method writes an mpint as defined in the SSH protocol:
             * - If the most significant bit would be set, a leading zero byte is added.
             * @param mpint The mpint to serialize
             */
            void writeMPInt(const secure_vector<uint8_t> &mpint);

            /**
             * @brief Write a multi-precision integer (mpint) to the data
             *
             * This is the same as writeMPInt for secure_vector, but accepts std::vector.
             * @param mpint The mpint to serialize
             */
            void writeMPInt(const std::vector<uint8_t> &mpint);

            /**
             * @brief Write raw data to the serializer
             * @param data The data to write
             */
            void writeRaw(const secure_vector<uint8_t> &data);

            /**
             * @brief Write raw data to the serializer
             * @param data The data to write
             */
            void writeRaw(const std::string &data);

            /**
             * @brief Finalize the serialization process (e.g., write length prefix at the beginning)
             * This should be called after all data has been written.
             */
            void finalize();

            /**
             * @brief Get the size of the serialized data
             * @return size_t The size of the serialized data
             */
            size_t size() const { return m_data.size(); }

            /**
             * @brief Get the serialized data
             * @return secure_vector<uint8_t> The serialized data
             */
            secure_vector<uint8_t> dataSecure() const;

            /**
             * @brief Get the serialized data
             * @return std::vector<uint8_t> The serialized data
             */
            std::vector<uint8_t> data() const;
            

        private:
            secure_vector<uint8_t> m_data;
        };
    } // namespace libssha
} // namespace nglab