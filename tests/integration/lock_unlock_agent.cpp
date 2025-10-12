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
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <libssha/messages/lock-message.h>
#include <libssha/messages/message.h>
#include <libssha/utils/secure_vector.h>

using nglab::libssha::LockMessage;
using nglab::libssha::UnlockMessage;
using nglab::libssha::Message;
using nglab::libssha::secure_vector;

/*
 * Using ssh-add in test scripts is complicated because it can't read password
 * from command line or environment variable. So we create a simple helper
 * program that connects to the agent socket and sends lock/unlock messages.
 */
int main(int argc, char **argv)
{
    if(argc!=2) {
        fprintf(stderr, "Usage: %s <lock|unlock>\n", argv[0]);
        return 1;
    }
    bool do_lock = false;
    if(strcmp(argv[1], "lock")==0) {
        do_lock = true;
    } else if(strcmp(argv[1], "unlock")==0) {
        do_lock = false;
    } else {
        fprintf(stderr, "Invalid argument: %s. Use 'lock' or 'unlock'.\n", argv[1]);
        return 1;
    }
    int s = -1;
    s=socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        perror("socket");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/test-socket", sizeof(addr.sun_path) - 1);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        close(s);
        return 1;
    }
    // Perform lock operation

    secure_vector<uint8_t> lock_data;

    secure_vector<uint8_t> password = {'t','e','s','t','p','a','s','s','w','o','r','d'};

    if(do_lock) {
        printf("Locking agent...\n");
        LockMessage lock_msg;
        lock_msg.setPassword(password);
        lock_data = lock_msg.serialize();

    } else {
        printf("Unlocking agent...\n");
        UnlockMessage unlock_msg;
        unlock_msg.setPassword(password);
        lock_data = unlock_msg.serialize();
    }
    write(s, lock_data.data(), lock_data.size());
    // Read lock response

    uint8_t buff[2048];
    ssize_t n = read(s, buff, sizeof(buff));
    Message resp_msg(buff, n);
    if (resp_msg.type() == nglab::libssha::SSH_AGENT_SUCCESS) {
        printf("Agent locked successfully.\n");
    } else {
        printf("Failed to lock agent.\n");
        close(s);
        return 1;
    }
}