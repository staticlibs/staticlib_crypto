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
 * File:   base64_sink_test.cpp
 * Author: alex
 *
 * Created on June 3, 2018, 8:56 PM
 */

#include "staticlib/crypto/base64_sink.hpp"

#include <array>
#include <iostream>

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

void test_sink() {
    auto src = sl::io::string_source("foo42\n");
    auto dest = sl::io::string_sink();
    {
        auto sink = sl::crypto::make_base64_sink(dest);
        std::array<char, 2> buf;
        sl::io::copy_all(src, sink, buf);
//        sink.flush();
    }
    
    slassert("Zm9vNDIK" == dest.get_string());
}

int main() {
    try {
        test_sink();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
