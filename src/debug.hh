#pragma once

#include "common.hh"

#include <format>
#include <print>
#include <string>
#include <string_view>

namespace oo {

enum class verbosity : u8
{
  nothing,
  error,
  warn,
  info,
  debug,
  all
};

forceinline constexpr const char *verbosity_to_string(verbosity v)
{
  switch (v) {
  case verbosity::error: return "ERR";
  case verbosity::info: return "INF";
  case verbosity::warn: return "WRN";
  case verbosity::debug: return "DBG";
  case verbosity::all: return "ALL";
  default: return "???";
  }
}

extern verbosity LOGGER_VERBOSITY;

} // namespace oo

namespace oo::debug {

#define trace(v, ...)                                                          \
  do {                                                                         \
    if ((v) <= oo::LOGGER_VERBOSITY) [[unlikely]] {                            \
      std::print(stderr, "[{}] {:>32} {:>32}(): ", oo::verbosity_to_string(v), \
                 std::string{__FILE__} + ":" + std::to_string(__LINE__),       \
                 __func__);                                                    \
      std::println(stderr, __VA_ARGS__);                                       \
    }                                                                          \
  } while (0)

#if defined __clang__
#include <cstdarg>
#include <string>
used static void t__strprintf(::std::string &s, const char *fmt, ...)
{
  va_list a;
  va_start(a, fmt);
  va_list ac;
  va_copy(ac, a);
  usize n = vsnprintf(nullptr, 0, fmt, ac);
  char *b = new char[n];
  unused(vsnprintf(b, n, fmt, a));
  s.append(b);
  delete[] b;
}

template <class T>
::std::string t__string_from_struct(const T &x)
{
  ::std::string s{};
  __builtin_dump_struct(&x, t__strprintf, s);
  return s;
}
#define struct_to_string(x) oo::debug::t__string_from_struct(x)
#endif // __clang__

#if !defined string_to_struct
#define string_to_struct(...) std::string{"<not supported>"}
#endif

#define t__va_are_empty(...) (sizeof((char[]) {#__VA_ARGS__}) == 1)

/* True if __VA_ARGS__ passed as an argument is empty. */
#define va_are_empty(...) t__va_are_empty(__VA_ARGS__)

#define debugtrap(...)                                                         \
  do {                                                                         \
    trace(oo::verbosity::error, "Encountered a debug trap");                   \
    if (!va_are_empty(__VA_ARGS__)) {                                          \
      trace(oo::verbosity::warn, "Details: " __VA_ARGS__);                     \
    }                                                                          \
    t__debugtrap();                                                            \
  } while (0)

#define unreachable(...)                                                       \
  do {                                                                         \
    trace(oo::verbosity::error, "Reached an unreachable statement");           \
    if (!va_are_empty(__VA_ARGS__)) {                                          \
      trace(oo::verbosity::error, "Details: " __VA_ARGS__);                    \
    }                                                                          \
    t__unreachable();                                                          \
  } while (0)

#define insist(x, ...)                                                         \
  do {                                                                         \
    if (!(x)) [[unlikely]] {                                                   \
      trace(oo::verbosity::error, "'insist(" #x ")' fail in {}().", __func__); \
      if (!va_are_empty(__VA_ARGS__)) {                                        \
        trace(oo::verbosity::error, "Details: " __VA_ARGS__);                  \
      }                                                                        \
      debugtrap();                                                             \
    }                                                                          \
  } while (0)

template <typename T>
forceinline auto t__format_arg(const char *name, const T &value)
    -> ::std::string
{
  if constexpr (requires { ::std::format("{}", value); }) {
    return ::std::format("{} = {}", name, value);
  } else {
    return ::std::format("{} = <unprintable>", name);
  }
}

template <typename T>
forceinline auto t__format_arg(const char *name, T *value) -> ::std::string
{
  if (value == nullptr) {
    return ::std::format("{} = nullptr", name);
  }
#if defined __clang__
  if constexpr (::std::is_class_v<T> && !::std::is_same_v<T, ::std::string>) {
    return ::std::format("{} = {} @ {}", name, struct_to_string(*value),
                         static_cast<const void *>(value));
  } else {
    return ::std::format("{} = {}", name, static_cast<const void *>(value));
  }
#else
  return ::std::format("{} = {}", name, static_cast<const void *>(value));
#endif
}

template <typename... Args>
forceinline auto t__format_args_impl(const char *names, Args &&...args)
    -> ::std::string
{
  ::std::string result;
  ::std::string_view names_view{names};
  auto format_one = [&](auto &&arg, bool is_last) {
    auto comma_pos = names_view.find(',');
    auto arg_name = (comma_pos != ::std::string_view::npos)
                        ? names_view.substr(0, comma_pos)
                        : names_view;

    while (!arg_name.empty() &&
           (arg_name.front() == ' ' || arg_name.front() == '\t'))
      arg_name.remove_prefix(1);
    while (!arg_name.empty() &&
           (arg_name.back() == ' ' || arg_name.back() == '\t'))
      arg_name.remove_suffix(1);

    result += t__format_arg(::std::string{arg_name}.c_str(), arg);
    if (!is_last) result += ", ";

    if (comma_pos != ::std::string_view::npos)
      names_view = names_view.substr(comma_pos + 1);
  };

  ::std::size_t idx = 0;
  (format_one(args, ++idx == sizeof...(args)), ...);
  return result;
}

#define trace_variables(v, ...)                                                \
  do {                                                                         \
    if ((v) <= oo::LOGGER_VERBOSITY) {                                         \
      if constexpr (va_are_empty(__VA_ARGS__)) {                               \
        trace(v, "()");                                                        \
      } else {                                                                 \
        trace(v, "({})",                                                       \
              oo::debug::t__format_args_impl(#__VA_ARGS__, __VA_ARGS__));      \
      }                                                                        \
    }                                                                          \
  } while (0)

#if defined __clang__
#define trace_self(v)                                                          \
  do {                                                                         \
    if ((v) <= oo::LOGGER_VERBOSITY) {                                         \
      trace(v, "this = {}", struct_to_string(*this));                          \
    }                                                                          \
  } while (0)
#else
#define trace_self(v) ((void) 0)
#endif

} // namespace oo::debug
