#pragma once

#include "debug.hh"

#include <format>
#include <string>

namespace oo {

struct error {
  enum code : i8 {
    unknown = -1,
  };

  error(std::string_view reason) : m_reason(reason) {};

  operator std::string_view() const noexcept { return get_reason(); }

  fn get_code() noexcept -> code { return m_code; };
  fn get_reason() const noexcept -> std::string_view { return m_reason; }
  fn get_owned_reason() const noexcept -> std::string { return m_reason; }

private:
  code m_code;
  std::string m_reason;
};

struct ok {};

constexpr auto strip_path_prefix(const char *path) -> const char * {
  if (path[0] == '.' && path[1] == '/') {
    return path + 2;
  }
  return path;
}

#define make_error(msg)                                                        \
  oo::error {                                                                  \
    ::std::format("{} ({}:{})", msg, oo::strip_path_prefix(__FILE__),          \
                  __LINE__)                                                    \
  }

template <typename V> struct error_or {
  error_or() : m_data() {}

  error_or(V v) : m_data(std::move(v)) {}
  error_or(error e) : m_data(std::move(e)) {}

  error_or(const error_or &other) : m_data(other.m_data) {}
  error_or(error_or &&other) noexcept : m_data(std::move(other.m_data)) {}

  error_or &operator=(const error_or &other) {
    if (this != &other) {
      m_data = other.m_data;
    }
    return *this;
  }

  error_or &operator=(error_or &&other) noexcept {
    if (this != &other) {
      m_data = std::move(other.m_data);
    }
    return *this;
  }

  // Destructor
  ~error_or() = default;

  bool is_err() const { return std::holds_alternative<error>(m_data); }
  explicit operator bool() const { return !is_err(); }

  V &get_value() {
    if (is_err())
      debugtrap(".get_value() called on an error");
    return std::get<V>(m_data);
  }
  V &operator*() { return get_value(); }

  V take() {
    if (is_err())
      debugtrap(".take() called on an error");
    return std::move(std::get<V>(m_data));
  }
  error get_error() const {
    if (!is_err())
      debugtrap(".get_error() called on a value");
    return std::get<error>(m_data);
  }

private:
  std::variant<V, error> m_data;
};

#define unwrap(error_or_value)                                                 \
  ({                                                                           \
    auto _r = (error_or_value);                                                \
    if (!_r)                                                                   \
      return _r.get_error();                                                   \
    _r.take();                                                                 \
  })

} // namespace oo
