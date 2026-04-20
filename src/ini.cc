#include "ini.hh"

#include "constants.hh"
#include "debug.hh"
#include "linux_util.hh"

#include <fstream>

namespace oo {

static fn trim(std::string_view s) -> std::string_view
{
  let begin = s.find_first_not_of(" \t\r");
  if (begin == std::string_view::npos) return {};
  let end = s.find_last_not_of(" \t\r");
  return s.substr(begin, end - begin + 1);
}

ini_file::ini_file(std::filesystem::path path) : m_path(std::move(path)) {}

ini_file::ini_file(ini_file &&other) noexcept
    : m_path(std::move(other.m_path)), m_entries(std::move(other.m_entries)),
      m_header(std::move(other.m_header)), m_dirty(other.m_dirty),
      m_loaded(other.m_loaded)
{
  other.m_dirty = false;
  other.m_loaded = false;
}

ini_file::~ini_file()
{
  if (m_dirty) {
    if (let r = flush(); r.is_err()) {
      trace(verbosity::error, "Failed to flush ini file {}: {}",
            m_path.string(), r.get_error().get_reason());
    }
  }
}

fn ini_file::load() -> error_or<ok>
{
  insist(!m_path.empty(), "ini_file constructed with empty path");

  m_entries.clear();
  m_loaded = true;
  m_dirty = false;

  std::error_code ec;
  if (!std::filesystem::exists(m_path, ec)) {
    unwrap(oo_error_code(ec, "Could not stat ini file " + m_path.string()));
    return ok{};
  }

  std::ifstream file(m_path);
  if (!file.is_open()) {
    return make_error("Could not open ini file for reading: " +
                      m_path.string() + ": " + linux::get_errno_string());
  }

  std::string line;
  usize line_no = 0;
  while (std::getline(file, line)) {
    ++line_no;
    if (line.size() > constants::INI_MAX_LINE) {
      return make_error("INI line exceeds limit at " + m_path.string() + ":" +
                        std::to_string(line_no));
    }
    let trimmed = trim(line);
    if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == ';') {
      continue;
    }

    if (trimmed.front() == '[') {
      if (trimmed.back() != ']' || trimmed.size() < 2) {
        return make_error("Malformed section header at " + m_path.string() +
                          ":" + std::to_string(line_no) + ": '" +
                          std::string{trimmed} + "'");
      }
      continue;
    }

    let eq = trimmed.find('=');
    if (eq == std::string_view::npos) {
      return make_error("Missing '=' at " + m_path.string() + ":" +
                        std::to_string(line_no) + ": '" + std::string{trimmed} +
                        "'");
    }

    let key = trim(trimmed.substr(0, eq));
    let value = trim(trimmed.substr(eq + 1));
    if (key.empty()) {
      return make_error("Empty key at " + m_path.string() + ":" +
                        std::to_string(line_no));
    }

    m_entries.push_back(entry{std::string{key}, std::string{value}});
    insist(!m_entries.back().key.empty(),
           "parser pushed an entry with empty key");
  }

  trace(verbosity::debug, "Loaded {} entries from {}", m_entries.size(),
        m_path.string());
  return ok{};
}

fn ini_file::flush() -> error_or<ok>
{
  std::error_code ec;
  let parent = m_path.parent_path();
  if (!parent.empty() && !std::filesystem::exists(parent, ec)) {
    std::filesystem::create_directories(parent, ec);
    unwrap(oo_error_code(ec, "Could not create parent directory for " +
                                 m_path.string()));
  }

  std::ofstream file(m_path, std::ios::out | std::ios::trunc);
  if (!file.is_open()) {
    return make_error("Could not open ini file for writing: " +
                      m_path.string() + ": " + linux::get_errno_string());
  }

  if (!m_header.empty()) {
    std::string_view view{m_header};
    while (!view.empty()) {
      let nl = view.find('\n');
      let chunk = (nl == std::string_view::npos) ? view : view.substr(0, nl);
      file << "# " << chunk << "\n";
      if (nl == std::string_view::npos) break;
      view.remove_prefix(nl + 1);
    }
  }

  for (const let &e : m_entries) {
    file << e.key << "=" << e.value << "\n";
  }

  if (!file.good()) {
    return make_error("Error writing to ini file: " + m_path.string() + ": " +
                      linux::get_errno_string());
  }

  m_dirty = false;
  trace(verbosity::debug, "Flushed {} entries to {}", m_entries.size(),
        m_path.string());
  return ok{};
}

fn ini_file::set(std::string_view key, std::string_view value) -> void
{
  for (let &e : m_entries) {
    if (e.key == key) {
      if (e.value != value) {
        e.value = std::string{value};
        m_dirty = true;
      }
      return;
    }
  }
  m_entries.push_back(entry{std::string{key}, std::string{value}});
  m_dirty = true;
}

fn ini_file::append(std::string_view key, std::string_view value) -> void
{
  m_entries.push_back(entry{std::string{key}, std::string{value}});
  m_dirty = true;
}

fn ini_file::remove(std::string_view key) -> bool
{
  for (let it = m_entries.begin(); it != m_entries.end(); ++it) {
    if (it->key == key) {
      m_entries.erase(it);
      m_dirty = true;
      return true;
    }
  }
  return false;
}

fn ini_file::find(std::string_view key) const -> std::optional<std::string>
{
  for (const let &e : m_entries) {
    if (e.key == key) return e.value;
  }
  return std::nullopt;
}

fn ini_file::set_header(std::string_view comment) -> void
{
  m_header = std::string{comment};
  m_dirty = true;
}

} // namespace oo
