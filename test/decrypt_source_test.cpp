/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   decrypt_source_test.cpp
 * Author: alex
 *
 * Created on June 4, 2018, 2:34 PM
 */

#include "staticlib/crypto/decrypt_source.hpp"

#include <array>
#include <iostream>

#include "openssl/evp.h"

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

void test_decrypt() {
    auto check_msg = std::string("The quick brown fox jumps over the lazy dog");
    auto src = sl::io::string_source("e06f63a711e8b7aa9f9440107d4680a117994380ea31d2a299b95302d439b9702c8e65a99236ec920704915cf1a98a44");
    auto sink = sl::io::string_sink();
    {
        auto hex = sl::io::make_hex_source(src);
        auto dec = sl::crypto::make_decrypt_source(hex, EVP_aes_256_cbc(), 
                "01234567890123456789012345678901", "0123456789012345");
        std::array<char, 2> buf;
        sl::io::copy_all(dec, sink, buf);
    }

    slassert(48 == sink.get_string().length());
    slassert(check_msg == sink.get_string().substr(0, check_msg.length()));
}

int main() {
    try {
        test_decrypt();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
