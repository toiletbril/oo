#pragma once

#include "common.hh"
#include "error.hh"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace oo {

// Flat key=value ini handler. Loads into an in-memory vector, allows edits,
// flushes on destruction. Comments begin with `#` or `;`. Lines starting with
// `[` are tolerated as section markers and must close with `]`, but section
// scoping is not applied to keys.
class ini_file
{
public:
  struct entry
  {
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

  fn entries() const -> const std::vector<entry> & { return m_entries; }

  // Sets a comment block written before entries on flush. Newlines split
  // into separate `# ` lines.
  fn set_header(std::string_view comment) -> void;

private:
  std::filesystem::path m_path;
  std::vector<entry> m_entries;
  std::string m_header;
  bool m_dirty{false};
  bool m_loaded{false};
};

} // namespace oo
