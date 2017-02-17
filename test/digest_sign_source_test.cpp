/*
 * Copyright 2016, alex at staticlibs.net
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
 * File:   digest_sign_source_test.cpp
 * Author: alex
 *
 * Created on July 15, 2016, 9:09 PM
 */

#include "staticlib/crypto/digest_sign_source.hpp"

#include <array>
#include <iostream>

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

namespace io = staticlib::io;
namespace sc = staticlib::crypto;

const std::string TEXT = "foo bar baz";
const std::string SIGNATURE = ""
        "9553aef514b5c005e46b864234c254bf7a792a77cde8b3fdf65385238ed292b0"
        "0a590571fb8fdb46be80431f4410ff7c2a7e2a6ddbbb2b029346a2c7e9d9a752"
        "f06e26a815fe860fb75a36cd3b2d0a2257a4ee625d6cf872396f85ede1cf04ce"
        "cac00e9bf44e6306af0ebf27c32a5357af2970a225eb6daaefb830ee1111634b"
        "9e7f9856e5bb79b1f16c901d212e96223f450909a6826430d41040c6e3fbd94f"
        "e2c021f5033bab692b86350d8f4eb14c163e7bf97d8d79dffdf089e2818fe021"
        "eac9b004928266898d8717972b08ac560cbea31a074e384948975c9ae189a0b1"
        "fbc4ddacb5a33853d9fb6ff7a9dad2cfeaa5704dd02f6c5076cd6cb06afe3019";
const std::string KEY_PATH = "../test/certificate/test.key";
const std::string KEY_PASSWORD = "test";

void test_sign() {
    auto src = sc::make_digest_sign_source(io::string_source(TEXT), KEY_PATH, KEY_PASSWORD);
    slassert(!src.is_bogus());
    auto sink = io::string_sink();
    std::array<char, 2> buf;
    io::copy_all(src, sink, buf);

    slassert(SIGNATURE == src.get_signature());
}

int main() {
    try {
        OpenSSL_add_all_algorithms();
        
        test_sign();
        
        EVP_cleanup();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
