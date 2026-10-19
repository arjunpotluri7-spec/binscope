// Minimal expected-style result type. <expected> is C++23; Binscope targets C++20.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace binscope {

struct Error {
    std::string message;
    std::uint64_t offset = 0;  // file offset the problem relates to, when meaningful
};

template <typename T>
class [[nodiscard]] Result {
public:
    // Implicit on purpose, like std::expected: `return value;` and `return error;` both work.
    // NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor)
    Result(T value) : data_(std::in_place_index<0>, std::move(value)) {}
    // NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor)
    Result(Error error) : data_(std::in_place_index<1>, std::move(error)) {}

    [[nodiscard]] bool ok() const noexcept { return data_.index() == 0; }
    explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] const T& value() const& { return std::get<0>(data_); }
    [[nodiscard]] T& value() & { return std::get<0>(data_); }
    [[nodiscard]] T&& value() && { return std::get<0>(std::move(data_)); }
    [[nodiscard]] const Error& error() const& { return std::get<1>(data_); }

    const T& operator*() const& { return value(); }
    T& operator*() & { return value(); }
    const T* operator->() const { return &value(); }
    T* operator->() { return &value(); }

    [[nodiscard]] T value_or(T fallback) const { return ok() ? value() : std::move(fallback); }

private:
    std::variant<T, Error> data_;
};

inline Error make_error(std::string message, std::uint64_t offset = 0) {
    return Error{std::move(message), offset};
}

}  // namespace binscope
