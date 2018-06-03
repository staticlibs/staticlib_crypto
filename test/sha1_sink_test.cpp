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
 * File:   sha1_sink_test.cpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:50 PM
 */

#include "staticlib/crypto/sha1_sink.hpp"

#include <array>
#include <iostream>

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

void test_hash() {
    sl::io::string_source src{"foo42\n"};
    auto sink = sl::crypto::make_sha1_sink(sl::io::string_sink{});
    std::array<char, 2> buf;
    sl::io::copy_all(src, sink, buf);
    
    slassert("36237c8404b36a617a141504240189b8dd4dba28" == sink.get_hash());
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
