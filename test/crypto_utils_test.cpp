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
 * File:   crypto_utils_test.cpp
 * Author: alex
 *
 * Created on July 16, 2016, 1:43 PM
 */

#include "staticlib/crypto/crypto_utils.hpp"

#include <iostream>

#include "staticlib/config/assert.hpp"

void test_hex() {
    std::string data = "foo";
    std::string hex = sl::crypto::to_hex(data);
    slassert(data ==  sl::crypto::from_hex(hex));
}

int main() {
    try {
        test_hex();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
