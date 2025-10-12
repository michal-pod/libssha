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
#include <libssha/key/key-factory.h>
#include <libssha/key/key-manager.h>
#include <libssha/providers/botan/botan-lock-provider.h>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  nglab::libssha::KeyFactory::initializeKeyTypes();
  nglab::libssha::KeyManager::setLockProvider(new nglab::libssha::BotanLockProvider());

  return RUN_ALL_TESTS();
}
