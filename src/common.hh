#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace oo {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

using uchar = u8;
using ichar = i8;

using usize = size_t;
using uintptr = uintptr_t;

// Dude.
#define fn auto
#define let auto

#if defined __GNUC__ || defined __clang__ || defined __COSMOCC__
#define t__used __attribute__((used))
#define t__forceinline inline __attribute__((always_inline))
#define t__unreachable() __builtin_unreachable()
#define t__debugtrap() __builtin_trap()
#else /* __GNUC__ || __clang__ || __COSMOCC__ */
#error Oh no! Segmentation fault. Please download a better compiler that \
       supports GNU extensions!
#define t__used        /* nothing */
#define t__forceinline /* nothing */
#define t__unreachable() abort()
#define t__debugtrap() abort()
#endif

#define used t__used
#define forceinline t__forceinline
#define unused(x) (::std::ignore = (x))

#define t__concat_literal(x, y) x##y
#define concat_literal(x, y) t__concat_literal(x, y)

template <typename T> struct t__exit_scope {
  t__exit_scope(T lambda) : m_lambda(lambda) {}
  ~t__exit_scope() { m_lambda(); }
  t__exit_scope(const t__exit_scope &);

private:
  T m_lambda;
  t__exit_scope &operator=(const t__exit_scope &);
};

struct t__exit_scope_help {
  template <typename T> t__exit_scope<T> operator+(T t) { return t; }
};

/* Defer a block until the end of the scope. */
#define defer                                                                  \
  const auto &concat_literal(defer__, __LINE__) = t__exit_scope_help() + [&]()

#define sub_sat(a, b) ((a) > (b) ? (a) - (b) : 0)

/* The length of statically allocated array. */
#define countof(arr) (sizeof(arr) / sizeof(*(arr)))

forceinline constexpr u64 hash_string(std::string_view s) {
  u64 h = 14695981039346656037u;
  for (const char &b : s) {
    h *= 1099511628211u;
    h ^= static_cast<unsigned char>(b);
  }
  return h;
}

#define string_switch(s) switch (hash_string(s))
#define string_case(s) case (hash_string(s))

} // namespace oo

#include "error.hh"

namespace oo {

fn ensure_runtime_dir_exists() -> error_or<ok>;

} // namespace oo
