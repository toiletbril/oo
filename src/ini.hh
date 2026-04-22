#pragma once

#include "common.hh"
#include "error.hh"

#include <filesystem>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace oo {

// A single parsed line from an INI file. Preserves round-trip structure: a
// file loaded and re-flushed is byte-equivalent modulo surrounding
// whitespace on entries.
class ini_line {
public:
  enum class kind { comment, section, entry, blank };

  virtual ~ini_line() = default;
  virtual fn get_kind() const -> kind = 0;
  virtual fn write_to(std::ostream &out) const -> void = 0;
};

class ini_comment : public ini_line {
public:
  explicit ini_comment(std::string text, char marker = '#')
      : m_text(std::move(text)), m_marker(marker) {}

  fn get_kind() const -> kind override { return kind::comment; }
  fn write_to(std::ostream &out) const -> void override {
    out << m_marker << ' ' << m_text << '\n';
  }

private:
  std::string m_text;
  char m_marker;
};

class ini_section : public ini_line {
public:
  explicit ini_section(std::string name) : m_name(std::move(name)) {}

  fn get_kind() const -> kind override { return kind::section; }
  fn write_to(std::ostream &out) const -> void override {
    out << '[' << m_name << "]\n";
  }

  fn get_name() const -> const std::string & { return m_name; }

private:
  std::string m_name;
};

class ini_entry : public ini_line {
public:
  ini_entry(std::string key, std::string value)
      : m_key(std::move(key)), m_value(std::move(value)) {}

  fn get_kind() const -> kind override { return kind::entry; }
  fn write_to(std::ostream &out) const -> void override {
    out << m_key << '=' << m_value << '\n';
  }

  fn get_key() const -> const std::string & { return m_key; }
  fn get_value() const -> const std::string & { return m_value; }
  fn set_value(std::string v) -> void { m_value = std::move(v); }

private:
  std::string m_key;
  std::string m_value;
};

class ini_blank : public ini_line {
public:
  fn get_kind() const -> kind override { return kind::blank; }
  fn write_to(std::ostream &out) const -> void override { out << '\n'; }
};

// Loads into an in-memory vector of tagged lines, allows entry edits, flushes
// on destruction. Comments begin with `#` or `;`. Lines starting with `[` are
// tolerated as section markers and must close with `]`, but section scoping
// is not applied to keys.
class ini_file {
public:
  // Back-compat alias for callers that still use the old struct form.
  struct entry {
    std::string key;
    std::string value;
  };

  explicit ini_file(std::filesystem::path path);
  ~ini_file();

  ini_file(ini_file &&other) noexcept;
  ini_file(const ini_file &) = delete;
  ini_file &operator=(const ini_file &) = delete;
  ini_file &operator=(ini_file &&) = delete;

  fn load() -> error_or<ok>;
  fn flush() -> error_or<ok>;

  // Replaces the first entry with the given key, or appends if absent.
  fn set(std::string_view key, std::string_view value) -> void;
  // Always appends a new entry, even if the key already exists.
  fn append(std::string_view key, std::string_view value) -> void;
  // Removes the first entry with the given key. Returns true if anything
  // was removed.
  fn remove(std::string_view key) -> bool;
  fn find(std::string_view key) const -> std::optional<std::string>;

  // Returns a snapshot of entries (comments and sections filtered out).
  fn entries() const -> std::vector<entry>;

  // Sets a comment block written before entries on flush. Newlines split
  // into separate `# ` lines. Stored as a sequence of ini_comment lines
  // at the top of the file.
  fn set_header(std::string_view comment) -> void;

private:
  std::filesystem::path m_path;
  std::vector<std::unique_ptr<ini_line>> m_lines;
  bool m_dirty{false};
  bool m_loaded{false};

  fn header_end_index() const -> usize;
  fn find_entry(std::string_view key) -> ini_entry *;
  fn find_entry_const(std::string_view key) const -> const ini_entry *;
};

} // namespace oo
