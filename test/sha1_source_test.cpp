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
 * File:   sha1_source_test.cpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:51 PM
 */

#include "staticlib/crypto/sha256_source.hpp"

#include <array>
#include <iostream>

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

void test_hash() {
    auto src = sl::crypto::make_sha256_source(sl::io::string_source("foo42\n"));
    auto sink = sl::io::string_sink();
    std::array<char, 2> buf;
    sl::io::copy_all(src, sink, buf);

    slassert("ee41b4f1a590fae151736f09890dbd98d0707421ad84fa25afe89e1e30006009" == src.get_hash());
}

int main() {
    try {
        test_hash();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
