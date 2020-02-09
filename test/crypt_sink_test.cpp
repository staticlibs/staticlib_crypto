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
 * File:   encrypt_sink_test.cpp
 * Author: alex
 *
 * Created on June 4, 2018, 2:15 PM
 */

#include "staticlib/crypto/crypt_sink.hpp"

#include <array>
#include <iostream>

#include "openssl/evp.h"

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

void test_encrypt() {
    auto src = sl::io::string_source("The quick brown fox jumps over the lazy dog");
    auto dest = sl::io::string_sink();
    {
        auto hex = sl::io::make_hex_sink(dest);
        auto sink = sl::crypto::make_encrypt_sink(hex, EVP_aes_256_cbc(),
                "01234567890123456789012345678901", "0123456789012345");
        std::array<char, 2> buf;
        sl::io::copy_all(src, sink, buf);
    }

    //std::cout << "[" << dest.get_string() << "]" << std::endl;
    slassert("e06f63a711e8b7aa9f9440107d4680a117994380ea31d2a299b95302d439b9702c8e65a99236ec920704915cf1a98a44"
            == dest.get_string());
}

void test_decrypt() {
    auto src = sl::io::string_source("e06f63a711e8b7aa9f9440107d4680a117994380ea31d2a299b95302d439b9702c8e65a99236ec920704915cf1a98a44");
    auto dest = sl::io::string_sink();
    {
        auto hex = sl::io::make_hex_source(src);
        auto sink = sl::crypto::make_decrypt_sink(dest, EVP_aes_256_cbc(),
                "01234567890123456789012345678901", "0123456789012345");
        std::array<char, 2> buf;
        sl::io::copy_all(hex, sink, buf);
    }

    slassert("The quick brown fox jumps over the lazy dog" == dest.get_string());
}

int main() {
    try {
        test_encrypt();
        test_decrypt();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
