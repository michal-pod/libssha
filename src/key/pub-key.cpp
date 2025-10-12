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
#include <libssha/key/pub-key.h>
#include <external/SHA256.h>
#include <external/base64.hpp>
#include <format>

namespace nglab
{
    namespace libssha
    {
        std::vector<uint8_t> PubKeyBase::pubKeyDigest() const
        {
            SHA256 sha256;
            sha256.update(m_pub_blob.data(), m_pub_blob.size());
            auto digest = sha256.digest();
            return std::vector<uint8_t>(digest.begin(), digest.end());
        }

        string PubKeyBase::fingerprint(FingerprintFormat format) const
        {
            auto digest = pubKeyDigest();

            if (format == Sha256Hex)
            {
                // Hex encode
                static const char hex_chars[] = "0123456789abcdef";
                std::string hex;
                hex.reserve(digest.size() * 2);
                for (auto byte : digest)
                {
                    hex.push_back(hex_chars[(byte >> 4) & 0x0F]);
                    hex.push_back(hex_chars[byte & 0x0F]);
                }
                return hex;
            }

            // Default to Sha256Base64
            // Base64 encode
            std::string b64 = base64::to_base64(std::string(reinterpret_cast<const char*>(digest.data()), digest.size()));

            while (!b64.empty() && b64.back() == '=') {
                b64.pop_back();
            }

            return "SHA256:" + b64;
        }

        std::vector<string> PubKeyBase::visualHostKey()
        {
            constexpr int FLDBASE = 8;
            constexpr int FLDSIZE_Y = FLDBASE + 1;
            constexpr int FLDSIZE_X = FLDBASE * 2 + 1;
            std::vector<char> symbols = {
                ' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^'};
            std::array<std::array<int, FLDSIZE_X>, FLDSIZE_Y> grid = {};
            int x = FLDSIZE_X / 2;
            int y = FLDSIZE_Y / 2;
            for(auto byte : pubKeyDigest()){
                uint8_t input = byte;
                for(int b = 0; b < 4; ++b){
                    x+=(input & 0x1 ? 1 : -1);
                    y+=(input & 0x2 ? 1 : -1);
                    x = std::clamp(x, 0, FLDSIZE_X - 1);
                    y = std::clamp(y, 0, FLDSIZE_Y - 1);
                    if(grid[y][x] < static_cast<int>(symbols.size()) - 2){
                        grid[y][x]++;
                    }
                    input >>= 2;
                }
            }

            std::vector<string> result;
            auto key_type = std::format("[{} {}]", family(), bits());
            std::string header = "+";
            size_t front_pad = (FLDSIZE_X - key_type.size()) / 2;
            header += std::string(front_pad, '-');
            header += key_type;
            size_t back_pad = FLDSIZE_X - key_type.size() - front_pad;
            header += std::string(back_pad, '-');
            header += "+";
            result.push_back(header);
            
            for (int row = 0; row < FLDSIZE_Y; ++row)
            {
                string line("|");
                for (int col = 0; col < FLDSIZE_X; ++col)
                {
                    if(row == FLDSIZE_Y / 2 && col == FLDSIZE_X / 2){
                        line += 'S';
                    }
                    else if(row == y && col == x){
                        line += 'E';
                    }
                    else{
                        line += symbols[grid[row][col]];
                    }
                }
                line += "|";
                result.push_back(line);
            }
            result.push_back("+----[SHA256]-----+");
            return result;
        }

        std::string PubKeyBase::authKeyLine(std::string comment)
        {
            std::string pub_key_b64 = base64::to_base64(std::string(reinterpret_cast<const char*>(m_pub_blob.data()), m_pub_blob.size()));
            
            return std::format("{} {} {}", m_type, pub_key_b64, comment);
        }

    } // namespace libssha
} // namespace nglab