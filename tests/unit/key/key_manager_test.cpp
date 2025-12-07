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
#include <libssha/key/key-manager.h>
#include <libssha/providers/botan/eddsa-key.h>
#include <libssha/messages/identities-answer.h>
#include <gtest/gtest.h>
#include <libssha/utils/secure_vector.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <libssha/utils/serializer.h>
#include <libssha/messages/add-identity.h>
#include <libssha/agent/session.h>
#include <thread>
#include <chrono>

// Helper to create a valid ed25519 key blob for testing
nglab::libssha::secure_vector<uint8_t> make_ed25519_blob(uint8_t pub_byte = 0x01, uint8_t priv_byte = 0x02) {
    nglab::libssha::Serializer s;
    std::string type = "ssh-ed25519";
    std::vector<uint8_t> pubkey(32, pub_byte);
    std::vector<uint8_t> privkey_seed(32, priv_byte);
    std::vector<uint8_t> privkey(privkey_seed);
    privkey.insert(privkey.end(), pubkey.begin(), pubkey.end());
    s.writeBlob(pubkey);
    s.writeSecureBlob(nglab::libssha::secure_vector<uint8_t>(privkey.begin(), privkey.end()));
    return s.dataSecure();
}

nglab::libssha::secure_vector<uint8_t> make_ed25519_pub_blob(uint8_t pub_byte = 0x01) {
    nglab::libssha::Serializer s;
    std::string type = "ssh-ed25519";
    std::vector<uint8_t> pubkey(32, pub_byte);
    s.writeString(type);
    s.writeBlob(pubkey);
    return s.dataSecure();
}

class DummySession : public nglab::libssha::Session {
public:
    DummySession() : nglab::libssha::LogEnabler("dummy-session"), Session() {}
    bool confirmRequest([[maybe_unused]] const nglab::libssha::KeyBase &key) override { return true; }
    bool send(nglab::libssha::secure_vector<uint8_t>&) override { return true; }
    bool requiresConfirmation(const nglab::libssha::KeyBasePtr) const override { return false; }
    std::string client() const override { return "dummy-client"; }
    bool processExtensionMessage([[maybe_unused]] const nglab::libssha::ExtensionMessage &msg) override { return false; }
};

class KeyManagerTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        nglab::libssha::KeyManager::instance().removeAllKeys();
    }
    void TearDown() override {
        nglab::libssha::KeyManager::instance().removeAllKeys();
    }
    DummySession session;
};

TEST_F(KeyManagerTestFixture, AddEd25519KeySuccess) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    std::string comment = "test-key";
    km.addKey("ssh-ed25519", blob, comment);

    auto list = km.listKeys(session);
    ASSERT_EQ(list.size(), 1);
    auto expected_pub_blob = make_ed25519_pub_blob();
    EXPECT_EQ(list[0].blob, std::vector<uint8_t>(expected_pub_blob.begin(), expected_pub_blob.end()));
    EXPECT_EQ(list[0].comment, comment);
}

TEST_F(KeyManagerTestFixture, AddDuplicateEd25519KeyReplacesOld) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    km.addKey("ssh-ed25519", blob, "first");
    km.addKey("ssh-ed25519", blob, "second");
    auto list = km.listKeys(session);
    ASSERT_EQ(list.size(), 1);
    EXPECT_EQ(list[0].comment, "second");
}

TEST_F(KeyManagerTestFixture, AddUnsupportedKeyTypeThrows) {
    auto& km = nglab::libssha::KeyManager::instance();
    nglab::libssha::secure_vector<uint8_t> blob(32, 0x02);
    EXPECT_THROW(km.addKey("ssh-unsupported", blob, "bad"), std::runtime_error);
}

TEST_F(KeyManagerTestFixture, RemoveKeyWorks) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    km.addKey("ssh-ed25519", blob, "to-remove");
    auto pub_blob = make_ed25519_pub_blob();
    km.removeKey(std::vector<uint8_t>(pub_blob.begin(), pub_blob.end()));
    auto list = km.listKeys(session);
    EXPECT_TRUE(list.empty());
}

TEST_F(KeyManagerTestFixture, RemoveKeyNotFoundDoesNothing) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    km.addKey("ssh-ed25519", blob, "present");
    std::vector<uint8_t> not_present(32, 0xFF);
    km.removeKey(not_present);
    auto list = km.listKeys(session);
    EXPECT_EQ(list.size(), 1);
}

TEST_F(KeyManagerTestFixture, RemoveAllKeysWorks) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob1 = make_ed25519_blob();
    auto blob2 = make_ed25519_blob(0x02, 0x03);
    km.addKey("ssh-ed25519", blob1, "one");
    km.addKey("ssh-ed25519", blob2, "two");
    km.removeAllKeys();
    auto list = km.listKeys(session);
    EXPECT_TRUE(list.empty());
}

TEST_F(KeyManagerTestFixture, SignDataSuccess) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    km.addKey("ssh-ed25519", blob, "signer");
    auto pub_blob = make_ed25519_pub_blob();
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> sig = km.signData(std::vector<uint8_t>(pub_blob.begin(), pub_blob.end()), data, 0);
    EXPECT_FALSE(sig.empty());
}

TEST_F(KeyManagerTestFixture, SignDataKeyNotFoundThrows) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    std::vector<uint8_t> not_present(32, 0xFF);
    EXPECT_THROW(km.signData(not_present, {'h', 'e', 'l', 'l', 'o'}, 0), std::runtime_error);
}

TEST_F(KeyManagerTestFixture, ListKeysReturnsAll) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob1 = make_ed25519_blob();
    auto blob2 = make_ed25519_blob(0x02, 0x03);
    km.addKey("ssh-ed25519", blob1, "one");
    km.addKey("ssh-ed25519", blob2, "two");
    auto list = km.listKeys(session);
    ASSERT_EQ(list.size(), 2);
    auto pub_blob1 = make_ed25519_pub_blob();
    auto pub_blob2 = make_ed25519_pub_blob(0x02);

    EXPECT_EQ(list[0].blob, std::vector<uint8_t>(pub_blob1.begin(), pub_blob1.end()));
    EXPECT_EQ(list[1].blob, std::vector<uint8_t>(pub_blob2.begin(), pub_blob2.end()));
    EXPECT_EQ(list[0].comment, "one");
    EXPECT_EQ(list[1].comment, "two");
}

TEST_F(KeyManagerTestFixture, CleanupExpiredKeysWorks) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob1 = make_ed25519_blob();
    auto blob2 = make_ed25519_blob(0x02, 0x03);
    auto key1 = km.addKey("ssh-ed25519", blob1, "short-lived");
    key1->setLifetime(1); // 1 second
    km.addKey("ssh-ed25519", blob2, "long-lived");

    std::this_thread::sleep_for(std::chrono::seconds(2));
    km.cleanupExpiredKeys();

    auto list = km.listKeys(session);
    ASSERT_EQ(list.size(), 1);
    auto pub_blob2 = make_ed25519_pub_blob(0x02);
    EXPECT_EQ(list[0].blob, std::vector<uint8_t>(pub_blob2.begin(), pub_blob2.end()));
    EXPECT_EQ(list[0].comment, "long-lived");
}

TEST_F(KeyManagerTestFixture, AddKeyFromAddIdentityMessage) {
    auto& km = nglab::libssha::KeyManager::instance();
    nglab::libssha::AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("from-message");
    auto blob = make_ed25519_blob();
    msg.setKeyBlob(blob);
    msg.setLifetime(5); // 5 seconds

    km.addKey(msg);

    auto list_msg = km.listKeys(session);
    ASSERT_EQ(list_msg.size(), 1);
    auto pub_blob = make_ed25519_pub_blob();
    EXPECT_EQ(list_msg[0].blob, std::vector<uint8_t>(pub_blob.begin(), pub_blob.end()));
    EXPECT_EQ(list_msg[0].comment, "from-message");
}

TEST_F(KeyManagerTestFixture, LockUnlockCallsKeyMethods) {
    auto& km = nglab::libssha::KeyManager::instance();
    auto blob = make_ed25519_blob();
    auto key = km.addKey("ssh-ed25519", blob, "lockable");
    nglab::libssha::secure_vector<uint8_t> pass = {1,2,3};
    key->setLifetime(10);
    km.lock(pass);
    EXPECT_TRUE(km.isLocked());
    km.unlock(pass);
    EXPECT_FALSE(km.isLocked());
}