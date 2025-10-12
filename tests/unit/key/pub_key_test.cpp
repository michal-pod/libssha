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
#include <gtest/gtest.h>
#include <libssha/key/pub-key.h>
#include <string>
#include <vector>

using namespace nglab::libssha;

class DummyPubKey : public PubKeyBase {
public:
    DummyPubKey(const std::vector<uint8_t>& blob)
        : PubKeyBase(blob) {}

    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature) const override {
        // Accept if signature equals data reversed
        std::vector<uint8_t> reversed(data.rbegin(), data.rend());
        return signature == reversed;
    }

    size_t bits() const override { return 123; }
    std::string family() const override { return "DUMMY"; }
};

TEST(PubKeyBaseTest, FingerprintIsSHA256Format)
{
    std::vector<uint8_t> blob = {1,2,3,4,5,6,7,8,9,10};
    DummyPubKey pub(blob);
    std::string fp = pub.fingerprint();
    EXPECT_TRUE(fp.starts_with("SHA256:"));
    EXPECT_FALSE(fp.empty());
}

TEST(PubKeyBaseTest, VisualHostKeyReturnsLines)
{
    std::vector<uint8_t> blob(32, 0x01);
    DummyPubKey pub(blob);
    auto lines = pub.visualHostKey();
    ASSERT_FALSE(lines.empty());
    EXPECT_TRUE(lines.front().find("[DUMMY 123]") != std::string::npos);
    EXPECT_TRUE(lines.back().find("SHA256") != std::string::npos);
}

TEST(PubKeyBaseTest, BitsAndFamily)
{
    std::vector<uint8_t> blob(10, 0xAA);
    DummyPubKey pub(blob);
    EXPECT_EQ(pub.bits(), 123);
    EXPECT_EQ(pub.family(), "DUMMY");
}

TEST(PubKeyBaseTest, VerifySignature)
{
    std::vector<uint8_t> blob;
    DummyPubKey pub(blob);
    std::vector<uint8_t> data = {1,2,3};
    std::vector<uint8_t> sig = {3,2,1};
    EXPECT_TRUE(pub.verify(data, sig));
    std::vector<uint8_t> bad_sig = {1,2,3};
    EXPECT_FALSE(pub.verify(data, bad_sig));
}
