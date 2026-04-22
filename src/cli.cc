#include "cli.hh"

#include "common.hh"
#include "debug.hh"

#include <cstring>
#include <print>
#include <string>
#include <vector>

#if !defined OO_VERSION
#define OO_VERSION "unkn"
#endif

#if !defined COMMIT_HASH
#define COMMIT_HASH "unkn"
#endif
#if !defined COMPILER_COMMAND
#define COMPILER_COMMAND "unkn"
#endif
#if !defined OS_INFO
#define OS_INFO "unkn"
#endif
#if !defined BUILD_MODE
#define BUILD_MODE "custom"
#endif
#if !defined ENVCXXFLAGS
#define ENVCXXFLAGS "none"
#endif

namespace oo::cli {

flag::flag(enum kind kind, char short_name, std::string_view long_name,
           std::string_view description)
    : m_kind(kind), m_short_name(short_name), m_long_name(long_name),
      m_description(description) {}

fn flag::kind() const -> enum kind { return m_kind; }
fn flag::get_short_name() const -> char { return m_short_name; }
fn flag::get_long_name() const -> std::string_view { return m_long_name; }
fn flag::get_description() const -> std::string_view { return m_description; }

flag_boolean::flag_boolean(char short_name, std::string_view long_name,
                           std::string_view description)
    : flag(kind::boolean, short_name, long_name, description) {}

fn flag_boolean::toggle() -> void { m_value = !m_value; }
fn flag_boolean::is_enabled() const -> bool { return m_value; }

flag_repeated_boolean::flag_repeated_boolean(char short_name,
                                             std::string_view long_name,
                                             std::string_view description)
    : flag(kind::repeated_boolean, short_name, long_name, description) {
  insist(long_name.empty(), "fuck you");
}

fn flag_repeated_boolean::increment() -> void { ++m_count; }
fn flag_repeated_boolean::get_count() const -> usize { return m_count; }

flag_string::flag_string(char short_name, std::string_view long_name,
                         std::string_view description)
    : flag(kind::string, short_name, long_name, description) {}

fn flag_string::set(std::string_view v) -> void {
  m_value = v;
  m_is_set = true;
}

fn flag_string::is_set() const -> bool { return m_is_set; }

fn flag_string::get_value() const -> std::string_view { return m_value; }

flag_many_strings::flag_many_strings(char short_name,
                                     std::string_view long_name,
                                     std::string_view description)
    : flag(kind::many_strings, short_name, long_name, description) {}

fn flag_many_strings::append(std::string_view v) -> void {
  m_values.emplace_back(v);
}

fn flag_many_strings::is_empty() const -> bool { return m_values.empty(); }

fn flag_many_strings::get_size() const -> usize { return m_values.size(); }

fn flag_many_strings::values() const -> std::span<const std::string> {
  return m_values;
}

static fn format_flag_name(const flag *f, bool is_long) -> std::string {
  if (is_long)
    return "--" + std::string{f->get_long_name()};
  return std::string{"-"} + f->get_short_name();
}

static fn find_flag(std::span<std::unique_ptr<flag>> flags,
                    const char *flag_start, bool is_long, flag **const out,
                    const char **value_start) -> bool {
  insist(out != nullptr);
  insist(value_start != nullptr);
  insist(flag_start != nullptr);

  *out = nullptr;
  *value_start = nullptr;

  if (!is_long) {
    for (let const &f : flags) {
      if (f->get_short_name() != '\0' && f->get_short_name() == *flag_start) {
        *out = f.get();
        *value_start = flag_start + 1;
        return true;
      }
    }
    return false;
  }

  /* Long flags: pick longest prefix match because one flag name
     might be a prefix of another. */
  usize best = 0;

  for (let const &f : flags) {
    usize len = f->get_long_name().length();
    if (len == 0 || len <= best)
      continue;
    if (std::memcmp(f->get_long_name().data(), flag_start, len) == 0) {
      *out = f.get();
      *value_start = flag_start + len;
      best = len;
    }
  }

  return best > 0;
}

static fn apply_value(flag *f, const char *value, bool is_long) -> void {
  unused(is_long);
  insist(f != nullptr);
  insist(value != nullptr);
  insist(f->kind() == flag::kind::string ||
         f->kind() == flag::kind::many_strings);

  if (f->kind() == flag::kind::string)
    static_cast<flag_string *>(f)->set(value);
  else
    static_cast<flag_many_strings *>(f)->append(value);
}

static fn parse_args_impl(std::span<std::unique_ptr<flag>> flags, int argc,
                          const char *const *argv)
    -> error_or<std::vector<std::string>> {
  if (argc <= 0)
    return {};

  std::vector<std::string> args;
  flag *prev_flag{};
  bool expect_value = false;
  bool prev_is_long = false;
  bool passthrough = false;

  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];

    if (expect_value) {
      expect_value = false;
      apply_value(prev_flag, arg, prev_is_long);
      continue;
    }

    if (passthrough || arg[0] != '-') {
      args.emplace_back(arg);
      continue;
    }

    bool is_long = arg[1] == '-';
    const char *start = arg + (is_long ? 2 : 1);

    /* Bare '-' or '--'. */
    if (*start == '\0') {
      if (is_long)
        passthrough = true;
      else
        args.emplace_back(arg);
      continue;
    }

    const char *cursor = start;
    bool combining = true;

    while (combining) {
      combining = false;

      flag *f{};
      const char *val{};

      if (!find_flag(flags, cursor, is_long, &f, &val)) {
        std::string s = "unknown flag '";
        s += is_long ? "--" : "-";
        if (!is_long) {
          s += *cursor;
        } else {
          std::string_view sv{cursor};
          let eq = sv.find('=');
          s += (eq != std::string_view::npos) ? sv.substr(0, eq) : sv;
        }
        s += "'";
        return make_error(s);
      }

      if (f->kind() == flag::kind::boolean ||
          f->kind() == flag::kind::repeated_boolean) {
        insist(f != nullptr);

        if (f->kind() == flag::kind::boolean)
          static_cast<flag_boolean *>(f)->toggle();
        else
          static_cast<flag_repeated_boolean *>(f)->increment();

        /* Combined short flags: -vAsn or repeated: -vvv */
        if (!is_long && *val != '\0') {
          ++cursor;
          combining = true;
          continue;
        }
      } else {
        /* String or many_strings. */
        if (*val == '\0') {
          expect_value = true;
        } else if (*val == '=') {
          ++val;
          if (*val == '\0') {
            return make_error("No value provided for '" +
                              format_flag_name(f, is_long) + "' flag");
          }
          apply_value(f, val, is_long);
        } else if (!is_long) {
          /* Short flag without separator: -oValue */
          apply_value(f, val, is_long);
        } else {
          return make_error("long flags require '=' between flag and value. "
                            "try '" +
                            format_flag_name(f, is_long) + "=" + val + "'");
        }
      }

      prev_flag = f;
      prev_is_long = is_long;
    }
  }

  if (expect_value) {
    return make_error("No value provided for '" +
                      format_flag_name(prev_flag, prev_is_long) + "' flag");
  }

  return args;
}

static fn
parse_args_until_subcommand_impl(std::span<std::unique_ptr<flag>> flags,
                                 int &argc, char **&argv)
    -> error_or<std::optional<std::string>> {
  if (argc <= 0)
    return {std::nullopt};

  flag *prev_flag{};
  bool expect_value = false;
  bool prev_is_long = false;
  bool passthrough = false;
  int subcommand_index = -1;

  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];

    if (expect_value) {
      expect_value = false;
      apply_value(prev_flag, arg, prev_is_long);
      continue;
    }

    if (passthrough || arg[0] != '-') {
      /* First positional arg is the subcommand. */
      subcommand_index = i;
      break;
    }

    bool is_long = arg[1] == '-';
    const char *start = arg + (is_long ? 2 : 1);

    /* Bare '-' or '--'. */
    if (*start == '\0') {
      if (is_long)
        passthrough = true;
      else {
        subcommand_index = i;
        break;
      }
      continue;
    }

    const char *cursor = start;
    bool combining = true;

    while (combining) {
      combining = false;

      flag *f{};
      const char *val{};

      if (!find_flag(flags, cursor, is_long, &f, &val)) {
        std::string s = "unknown flag '";
        s += is_long ? "--" : "-";
        if (!is_long) {
          s += *cursor;
        } else {
          std::string_view sv{cursor};
          let eq = sv.find('=');
          s += (eq != std::string_view::npos) ? sv.substr(0, eq) : sv;
        }
        s += "'";
        return make_error(s);
      }

      if (f->kind() == flag::kind::boolean ||
          f->kind() == flag::kind::repeated_boolean) {
        insist(f != nullptr);

        if (f->kind() == flag::kind::boolean)
          static_cast<flag_boolean *>(f)->toggle();
        else
          static_cast<flag_repeated_boolean *>(f)->increment();

        if (!is_long && *val != '\0') {
          ++cursor;
          combining = true;
          continue;
        }
      } else {
        if (*val == '\0') {
          expect_value = true;
        } else if (*val == '=') {
          ++val;
          if (*val == '\0') {
            return make_error("No value provided for '" +
                              format_flag_name(f, is_long) + "' flag");
          }
          apply_value(f, val, is_long);
        } else if (!is_long) {
          apply_value(f, val, is_long);
        } else {
          return make_error("long flags require '=' between flag and value. "
                            "try '" +
                            format_flag_name(f, is_long) + "=" + val + "'");
        }
      }

      prev_flag = f;
      prev_is_long = is_long;
    }
  }

  if (expect_value) {
    return make_error("No value provided for '" +
                      format_flag_name(prev_flag, prev_is_long) + "' flag");
  }

  if (subcommand_index < 0)
    return {std::nullopt};

  std::string subcommand = argv[subcommand_index];

  /* Update argc/argv to point to args after the subcommand. */
  argc = argc - subcommand_index - 1;
  argv = argv + subcommand_index + 1;

  return std::optional<std::string>{subcommand};
}

fn cli::add_use_case(std::string_view pattern, std::string_view description)
    -> void {
  m_use_cases.push_back({std::string{pattern}, std::string{description}});
}

fn cli::reset_context() -> void {
  m_flags.clear();
  m_use_cases.clear();
}

fn cli::parse_args_until_subcommand() -> error_or<std::optional<std::string>> {
  insist(m_argv != nullptr,
         "cli::m_argv must not be null for argument parsing");
  return parse_args_until_subcommand_impl(m_flags, m_argc, m_argv);
}

fn cli::parse_args() -> error_or<std::vector<std::string>> {
  insist(m_argv != nullptr,
         "cli::m_argv must not be null for argument parsing");
  return parse_args_impl(m_flags, m_argc, m_argv);
}

static fn wrap_text(std::string_view text, usize width, usize indent)
    -> std::string {
  std::string result;
  std::string indent_str(indent, ' ');
  usize pos = 0;

  while (pos < text.length()) {
    if (pos > 0) {
      result += '\n' + indent_str;
    }

    usize line_len = std::min(width - indent, text.length() - pos);
    if (pos + line_len < text.length()) {
      usize last_space = text.rfind(' ', pos + line_len);
      if (last_space != std::string_view::npos && last_space > pos) {
        line_len = last_space - pos;
      }
    }

    result += text.substr(pos, line_len);
    pos += line_len;
    if (pos < text.length() && text[pos] == ' ') {
      ++pos;
    }
  }

  return result;
}

fn cli::show_help() const -> void {
  std::string s;

  if (!m_use_cases.empty()) {
    s += "USAGE\n";
    for (let const &uc : m_use_cases) {
      s += "  " + uc.pattern + "\n";
      if (!uc.description.empty()) {
        s += "  " + wrap_text(uc.description, 80, 2) + "\n";
      }
      s += "\n";
    }
  }

  static constexpr usize MAX_WIDTH = 24;
  static constexpr usize STRING_EXTRA = 11;
  static constexpr usize MANY_STRINGS_EXTRA = 11;
  static constexpr usize REPEATED_BOOLEAN_EXTRA = 5;

  if (!m_flags.empty()) {
    s += "OPTIONS\n";

    for (let const &f : m_flags) {
      let has_short = f->get_short_name() != '\0';

      std::string flag_part;
      if (has_short) {
        flag_part += "  -";
        flag_part += f->get_short_name();
        if (f->kind() == flag::kind::repeated_boolean)
          flag_part += std::string{"["} + f->get_short_name() + "..]";
      }

      if (!f->get_long_name().empty()) {
        flag_part += has_short ? ", " : "      ";
        flag_part += "--";
        flag_part += f->get_long_name();

        if (f->kind() == flag::kind::string)
          flag_part += "=<..>      ";
        else if (f->kind() == flag::kind::many_strings)
          flag_part += "=<..>, <..>";
      } else {
        flag_part += "    ";
      }

      usize prefix_len = has_short ? 4 : 2;
      usize flag_len =
          (f->get_long_name().empty() ? 0 : 2 + f->get_long_name().length());
      usize extra =
          (flag::kind::string == f->kind())             ? STRING_EXTRA
          : (flag::kind::many_strings == f->kind())     ? MANY_STRINGS_EXTRA
          : (flag::kind::repeated_boolean == f->kind()) ? REPEATED_BOOLEAN_EXTRA
                                                        : 0;
      usize total = prefix_len + flag_len + extra;

      if (total < MAX_WIDTH) {
        for (usize i = 0; i < MAX_WIDTH - total; i++)
          flag_part += ' ';
      }

      s += flag_part;
      s += wrap_text(f->get_description(), 80, flag_part.length());
      s += "\n";
    }
  }

  std::print(stderr, "{}", s);
}

fn show_version() -> void {
  std::println(stderr, "{}-{}-{}\n\n{}{}\n{}", OO_VERSION, BUILD_MODE,
               COMMIT_HASH, COMPILER_COMMAND, ENVCXXFLAGS, OS_INFO);
}

fn show_message(std::string_view err) -> void {
  std::println(stderr, "oo: {}", err);
}

} // namespace oo::cli
