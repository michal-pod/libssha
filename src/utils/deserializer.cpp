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
#include <libssha/utils/deserializer.h>
#include <stdexcept>
#include <cstring>
#include <libssha/key/key-factory.h>

namespace nglab
{
    namespace libssha
    {

        Deserializer::Deserializer(const unsigned char *data, size_t length)
            : m_data(data), m_length(length), m_offset(0)
        {
        }

        Deserializer::Deserializer(const std::string &data)
            : m_data(reinterpret_cast<const unsigned char *>(data.data())),
              m_length(data.size()), m_offset(0)
        {
        }

        uint32_t Deserializer::readBE32()
        {
            if (m_offset + 4 > m_length)
                throw std::out_of_range("Not enough data to read uint32_t");
            uint32_t value = (static_cast<uint32_t>(m_data[m_offset]) << 24) |
                             (static_cast<uint32_t>(m_data[m_offset + 1]) << 16) |
                             (static_cast<uint32_t>(m_data[m_offset + 2]) << 8) |
                             (static_cast<uint32_t>(m_data[m_offset + 3]));
            m_offset += 4;
            return value;
        }

        std::vector<uint8_t> Deserializer::readBlob()
        {
            uint32_t len = readBE32();
            if (m_offset + len > m_length)
                throw std::out_of_range("Not enough data to read blob");
            std::vector<uint8_t> result(m_data + m_offset, m_data + m_offset + len);
            m_offset += len;
            return result;
        }

        void Deserializer::discardBlob()
        {
            uint32_t len = readBE32();
            if (m_offset + len > m_length)
                throw std::out_of_range("Not enough data to discard blob");
            m_offset += len;
        }

        secure_vector<uint8_t> Deserializer::readBlobSecure()
        {
            uint32_t len = readBE32();
            if (m_offset + len > m_length)
                throw std::out_of_range("Not enough data to read secure blob");

            secure_vector<uint8_t> result(m_data + m_offset, m_data + m_offset + len);
            m_offset += len;
            return result;
        }

        uint8_t Deserializer::readByte()
        {
            if (m_offset + 1 > m_length)
                throw std::out_of_range("Not enough data to read byte");
            return m_data[m_offset++];
        }

        std::vector<uint8_t> Deserializer::slice(size_t start, size_t end) const
        {
            if (start > end || end > m_length)
                throw std::out_of_range("Invalid slice range");
            return std::vector<uint8_t>(m_data + start, m_data + end);
        }

        secure_vector<uint8_t> Deserializer::sliceSecure(size_t start, size_t end) const
        {
            if (start > end || end > m_length)
                throw std::out_of_range("Invalid slice range");
            return secure_vector<uint8_t>(m_data + start, m_data + end);
        }

        std::vector<uint8_t> Deserializer::readMPInt()
        {
            uint32_t len = readBE32();
            if (m_offset + len > m_length)
                throw std::out_of_range("Not enough data to read mpint");
            std::vector<uint8_t> result(m_data + m_offset, m_data + m_offset + len);
            if (result.size() > 1 && result[0] == 0x00 && (result[1] & 0x80))
            {
                // Remove leading zero if not needed
                result.erase(result.begin());
            }
            m_offset += len;
            return result;
        }

        secure_vector<uint8_t> Deserializer::readMPIntSecure()
        {
            uint32_t len = readBE32();
            if (m_offset + len > m_length)
                throw std::out_of_range("Not enough data to read mpint");
            secure_vector<uint8_t> result(m_data + m_offset, m_data + m_offset + len);
            if (result.size() > 1 && result[0] == 0x00 && (result[1] & 0x80))
            {
                // Remove leading zero if not needed
                result.erase(result.begin());
            }
            m_offset += len;
            return result;
        }

        std::string Deserializer::readString()
        {
            auto blob = readBlob();
            return std::string(reinterpret_cast<const char *>(blob.data()), blob.size());
        }

        Deserializer::~Deserializer() = default;

    } // namespace libssha
} // namespace nglab
