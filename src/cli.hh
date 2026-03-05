#pragma once

#include "common.hh"
#include "error.hh"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace oo::cli {

struct flag {
  enum class kind : u8 {
    boolean,
    repeated_boolean,
    string,
    many_strings,
  };

  flag(const flag &) = delete;
  flag &operator=(const flag &) = delete;
  virtual ~flag() = default;

  fn kind() const -> enum kind;
  fn get_short_name() const -> char;
  fn get_long_name() const -> std::string_view;
  fn get_description() const -> std::string_view;

protected:
  flag(enum kind kind, char short_name, std::string_view long_name,
       std::string_view description);

  enum kind m_kind;
  char m_short_name;
  std::string m_long_name;
  std::string m_description;
};

struct flag_boolean : flag {
  flag_boolean(char short_name, std::string_view long_name,
               std::string_view description);

  fn toggle() -> void;
  fn is_enabled() const -> bool;

private:
  bool m_value{false};
};

struct flag_repeated_boolean : flag {
  flag_repeated_boolean(char short_name, std::string_view long_name,
                        std::string_view description);

  fn increment() -> void;
  fn get_count() const -> usize;

private:
  usize m_count{0};
};

struct flag_string : flag {
  flag_string(char short_name, std::string_view long_name,
              std::string_view description);

  fn set(std::string_view v) -> void;
  fn is_set() const -> bool;
  fn get_value() const -> std::string_view;

private:
  bool m_is_set{false};
  std::string m_value;
};

struct flag_many_strings : flag {
  flag_many_strings(char short_name, std::string_view long_name,
                    std::string_view description);

  fn append(std::string_view v) -> void;
  fn get_size() const -> usize;
  fn is_empty() const -> bool;
  fn values() const -> std::span<const std::string>;

private:
  std::vector<std::string> m_values;
};

struct use_case {
  std::string pattern;
  std::string description;
};

struct cli {
  cli(int argc, char **argv) : m_argc(argc), m_argv(argv) {}

  template <typename T, typename... Args> fn add_flag(Args &&...args) -> T & {
    auto p = std::make_unique<T>(std::forward<Args>(args)...);
    T &ref = *p;
    m_flags.push_back(std::move(p));
    return ref;
  }

  fn add_use_case(std::string_view pattern, std::string_view description)
      -> void;
  fn reset_context() -> void;

  fn parse_args() -> error_or<std::vector<std::string>>;
  fn parse_args_until_subcommand() -> error_or<std::optional<std::string>>;
  fn show_help() const -> void;

private:
  int m_argc;
  char **m_argv;

  std::vector<std::unique_ptr<flag>> m_flags;
  std::vector<use_case> m_use_cases;
};

fn show_version() -> void;

fn show_message(std::string_view err) -> void;

} // namespace oo::cli
