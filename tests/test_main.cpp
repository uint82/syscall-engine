#include "test_harness.hpp"

#include <cstdio>
#include <utility>

namespace testing {

std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

Registrar::Registrar(std::string name, std::function<void()> body) {
    registry().push_back({std::move(name), std::move(body)});
}

[[noreturn]] void report_failure(const char* file, int line, const std::string& message) {
    throw Failure{std::string(file) + ":" + std::to_string(line) + ": " + message};
}

int run_all() {
    std::size_t failed = 0;
    for (const auto& test : registry()) {
        try {
            test.body();
            std::printf("[pass] %s\n", test.name.c_str());
        } catch (const Failure& failure) {
            ++failed;
            std::printf("[fail] %s\n       %s\n", test.name.c_str(), failure.message.c_str());
        }
    }
    std::printf("%zu of %zu tests passed\n", registry().size() - failed, registry().size());
    return failed == 0 ? 0 : 1;
}

}

int main() {
    return testing::run_all();
}
