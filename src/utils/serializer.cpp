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
#include <libssha/utils/serializer.h>
#include <stdexcept>
#include <cstring>
#include <limits>

namespace nglab
{
namespace libssha
{

namespace {
constexpr size_t MAX_SERIALIZED_SIZE = 256 * 1024;
}

void Serializer::writeBE32(uint32_t value, size_t at)
{
    if (at == static_cast<size_t>(-1)) {
        if (m_data.size() + 4 > MAX_SERIALIZED_SIZE)
            throw std::length_error("Serializer: message too large");
        m_data.push_back((value >> 24) & 0xFF);
        m_data.push_back((value >> 16) & 0xFF);
        m_data.push_back((value >> 8) & 0xFF);
        m_data.push_back(value & 0xFF);
    } else {
        if (at + 4 > m_data.size())
            throw std::out_of_range("Serializer: writeBE32 at out of range");
        m_data[at]     = (value >> 24) & 0xFF;
        m_data[at + 1] = (value >> 16) & 0xFF;
        m_data[at + 2] = (value >> 8) & 0xFF;
        m_data[at + 3] = value & 0xFF;
    }
}

void Serializer::writeString(const std::string &str)
{
    writeBlob(std::vector<uint8_t>(str.begin(), str.end()));
}

void Serializer::writeBlob(const std::vector<uint8_t> &blob)
{
    if (m_data.size() + 4 + blob.size() > MAX_SERIALIZED_SIZE)
        throw std::length_error("Serializer: message too large");
    writeBE32(static_cast<uint32_t>(blob.size()));
    m_data.insert(m_data.end(), blob.begin(), blob.end());
}

void Serializer::writeSecureBlob(const secure_vector<uint8_t> &blob)
{
    if (m_data.size() + 4 + blob.size() > MAX_SERIALIZED_SIZE)
        throw std::length_error("Serializer: message too large");
    writeBE32(static_cast<uint32_t>(blob.size()));
    m_data.insert(m_data.end(), blob.begin(), blob.end());
}

void Serializer::writeByte(uint8_t byte, size_t at)
{
    if (at == static_cast<size_t>(-1)) {
        if (m_data.size() + 1 > MAX_SERIALIZED_SIZE)
            throw std::length_error("Serializer: message too large");
        m_data.push_back(byte);
    } else {
        if (at >= m_data.size())
            throw std::out_of_range("Serializer: writeByte at out of range");
        m_data[at] = byte;
    }
}

void Serializer::finalize()
{
    if (m_data.size() < 4)
        throw std::runtime_error("Serializer: not enough data to finalize");
    uint32_t len = static_cast<uint32_t>(m_data.size() - 4);
    writeBE32(len, 0);
}

secure_vector<uint8_t> Serializer::dataSecure() const
{
    return m_data;
}

std::vector<uint8_t> Serializer::data() const
{
    return std::vector<uint8_t>(m_data.begin(), m_data.end());
}

void Serializer::writeRaw(const secure_vector<uint8_t> &data)
{
    if (m_data.size() + data.size() > MAX_SERIALIZED_SIZE)
        throw std::length_error("Serializer: message too large");
    m_data.insert(m_data.end(), data.begin(), data.end());
}

void Serializer::writeRaw(const std::string& data)
{
    if (m_data.size() + data.size() > MAX_SERIALIZED_SIZE)
        throw std::length_error("Serializer: message too large");
    m_data.insert(m_data.end(), data.begin(), data.end());
}

void Serializer::writeMPInt(const secure_vector<uint8_t> &mpint)
{
    if (mpint.empty()) {
        writeBE32(0);
        return;
    }

    bool prepend_zero = (mpint[0] & 0x80) != 0;
    size_t length = mpint.size() + (prepend_zero ? 1 : 0);  

    if (m_data.size() + 4 + length > MAX_SERIALIZED_SIZE)
        throw std::length_error("Serializer: message too large");

    writeBE32(static_cast<uint32_t>(length));
    if (prepend_zero) {
        m_data.push_back(0x00);
    }
    m_data.insert(m_data.end(), mpint.begin(), mpint.end());
}

void Serializer::writeMPInt(const std::vector<uint8_t> &mpint)
{
    if (mpint.empty()) {
        writeBE32(0);
        return;
    }

    bool prepend_zero = (mpint[0] & 0x80) != 0;
    size_t length = mpint.size() + (prepend_zero ? 1 : 0);  

    if (m_data.size() + 4 + length > MAX_SERIALIZED_SIZE)
        throw std::length_error("Serializer: message too large");

    writeBE32(static_cast<uint32_t>(length));
    if (prepend_zero) {
        m_data.push_back(0x00);
    }
    m_data.insert(m_data.end(), mpint.begin(), mpint.end());
}
} // namespace libssha
} // namespace nglab
