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
#include <libssha/key/key.h>
#include <libssha/extensions/openssh-restrict-destination.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

namespace {
    constexpr const char type_name[] = "dummy-type";
}

class DummyKey : public nglab::libssha::Key<DummyKey, type_name>
{
public:
    DummyKey() = default;
    std::vector<uint8_t> pubBlob() override { return std::vector<uint8_t>{0x01, 0x02, 0x03}; }
    std::string fingerprint(nglab::libssha::PubKeyBase::FingerprintFormat type = nglab::libssha::PubKeyBase::FingerprintFormat::Sha256Base64) const override { return "dummy-fingerprint"; }
    std::vector<uint8_t> sign(const std::vector<uint8_t> &data, uint32_t flags) const override { return std::vector<uint8_t>{0x04, 0x05, 0x06}; }
    void lock(nglab::libssha::secure_vector<uint8_t>& password) override {
        // FIXME: implement key locking
        locked = true;
        last_password = password;
    }
    bool unlock(nglab::libssha::secure_vector<uint8_t>& password) override {
        // FIXME: implement key unlocking
        locked = false;
        last_password = password;
        return true;
    }
    bool locked = false;
    nglab::libssha::secure_vector<uint8_t> last_password;
};

TEST(KeyBaseTest, CommentGetterSetter)
{
    DummyKey key;
    key.setComment("test-comment");
    EXPECT_EQ(key.comment(), "test-comment");
}

TEST(KeyBaseTest, LifetimeAndExpired)
{
    DummyKey key;
    key.setLifetime(1); // 1 second lifetime
    EXPECT_FALSE(key.expired());
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_TRUE(key.expired());
}

TEST(KeyBaseTest, ConfirmRequiredFlag)
{
    DummyKey key;
    key.setConfirmRequired(true);
    EXPECT_TRUE(key.confirmRequired());
    key.setConfirmRequired(false);
    EXPECT_FALSE(key.confirmRequired());
}

TEST(KeyBaseTest, LockUnlockStub)
{
    DummyKey key;
    nglab::libssha::secure_vector<uint8_t> pass = {1,2,3};
    key.lock(pass);
    EXPECT_TRUE(key.locked);
    EXPECT_EQ(key.last_password, pass);
    key.unlock(pass);
    EXPECT_FALSE(key.locked);
    EXPECT_EQ(key.last_password, pass);
}

// Constraints will be tested in integration tests