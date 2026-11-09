#pragma once

#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace testing {

struct Failure {
    std::string message;
};

struct Case {
    std::string name;
    std::function<void()> body;
};

std::vector<Case>& registry();

struct Registrar {
    Registrar(std::string name, std::function<void()> body);
};

[[noreturn]] void report_failure(const char* file, int line, const std::string& message);

template <typename T>
std::string describe_value(const T& value) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
}

int run_all();

}

#define SC_DETAIL_CONCAT_INNER(a, b) a##b
#define SC_DETAIL_CONCAT(a, b) SC_DETAIL_CONCAT_INNER(a, b)

#define SC_DETAIL_TEST_CASE(name, id)                                        \
    static void SC_DETAIL_CONCAT(sc_test_body_, id)();                       \
    static ::testing::Registrar SC_DETAIL_CONCAT(sc_test_registration_, id)( \
        name, SC_DETAIL_CONCAT(sc_test_body_, id));                          \
    static void SC_DETAIL_CONCAT(sc_test_body_, id)()

#define SC_TEST_CASE(name) SC_DETAIL_TEST_CASE(name, __COUNTER__)

#define SC_REQUIRE(expression)                                           \
    do {                                                                 \
        if (!(expression)) {                                             \
            ::testing::report_failure(__FILE__, __LINE__, #expression);  \
        }                                                                \
    } while (false)

#define SC_REQUIRE_EQ(expected, actual)                                  \
    do {                                                                 \
        if (!((expected) == (actual))) {                                 \
            ::testing::report_failure(                                   \
                __FILE__, __LINE__,                                      \
                std::string(#expected " equals " #actual ", expected ") + \
                    ::testing::describe_value(expected) +                \
                    ", actual " + ::testing::describe_value(actual));    \
        }                                                                \
    } while (false)
