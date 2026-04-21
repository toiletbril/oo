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
    : m_path(std::move(other.m_path)), m_lines(std::move(other.m_lines)),
      m_dirty(other.m_dirty), m_loaded(other.m_loaded)
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

  m_lines.clear();
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
    if (trimmed.empty()) {
      m_lines.push_back(std::make_unique<ini_blank>());
      continue;
    }
    if (trimmed.front() == '#' || trimmed.front() == ';') {
      const char marker = trimmed.front();
      let body = trim(trimmed.substr(1));
      m_lines.push_back(
          std::make_unique<ini_comment>(std::string{body}, marker));
      continue;
    }

    if (trimmed.front() == '[') {
      if (trimmed.back() != ']' || trimmed.size() < 2) {
        return make_error("Malformed section header at " + m_path.string() +
                          ":" + std::to_string(line_no) + ": '" +
                          std::string{trimmed} + "'");
      }
      let name = trim(trimmed.substr(1, trimmed.size() - 2));
      m_lines.push_back(std::make_unique<ini_section>(std::string{name}));
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

    m_lines.push_back(
        std::make_unique<ini_entry>(std::string{key}, std::string{value}));
    insist(!static_cast<const ini_entry &>(*m_lines.back()).get_key().empty(),
           "parser pushed an entry with empty key");
  }

  trace(verbosity::debug, "Loaded {} lines from {}", m_lines.size(),
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

  for (const let &line : m_lines) {
    line->write_to(file);
  }

  if (!file.good()) {
    return make_error("Error writing to ini file: " + m_path.string() + ": " +
                      linux::get_errno_string());
  }

  m_dirty = false;
  trace(verbosity::debug, "Flushed {} lines to {}", m_lines.size(),
        m_path.string());

  return ok{};
}

fn ini_file::find_entry(std::string_view key) -> ini_entry *
{
  for (let &line : m_lines) {
    if (line->get_kind() != ini_line::kind::entry) continue;
    auto *e = static_cast<ini_entry *>(line.get());
    if (e->get_key() == key) return e;
  }
  return nullptr;
}

fn ini_file::find_entry_const(std::string_view key) const -> const ini_entry *
{
  for (const let &line : m_lines) {
    if (line->get_kind() != ini_line::kind::entry) continue;
    const auto *e = static_cast<const ini_entry *>(line.get());
    if (e->get_key() == key) return e;
  }
  return nullptr;
}

fn ini_file::set(std::string_view key, std::string_view value) -> void
{
  if (auto *e = find_entry(key); e != nullptr) {
    if (e->get_value() != value) {
      e->set_value(std::string{value});
      m_dirty = true;
    }
    return;
  }
  m_lines.push_back(
      std::make_unique<ini_entry>(std::string{key}, std::string{value}));
  m_dirty = true;
}

fn ini_file::append(std::string_view key, std::string_view value) -> void
{
  m_lines.push_back(
      std::make_unique<ini_entry>(std::string{key}, std::string{value}));
  m_dirty = true;
}

fn ini_file::remove(std::string_view key) -> bool
{
  for (let it = m_lines.begin(); it != m_lines.end(); ++it) {
    if ((*it)->get_kind() != ini_line::kind::entry) continue;
    const auto *e = static_cast<const ini_entry *>(it->get());
    if (e->get_key() == key) {
      m_lines.erase(it);
      m_dirty = true;
      return true;
    }
  }
  return false;
}

fn ini_file::find(std::string_view key) const -> std::optional<std::string>
{
  if (const auto *e = find_entry_const(key); e != nullptr) {
    return e->get_value();
  }
  return std::nullopt;
}

fn ini_file::entries() const -> std::vector<entry>
{
  std::vector<entry> out;
  for (const let &line : m_lines) {
    if (line->get_kind() != ini_line::kind::entry) continue;
    const auto *e = static_cast<const ini_entry *>(line.get());
    out.push_back(entry{e->get_key(), e->get_value()});
  }
  return out;
}

fn ini_file::header_end_index() const -> usize
{
  usize i = 0;
  for (; i < m_lines.size(); ++i) {
    const let kind = m_lines[i]->get_kind();
    if (kind != ini_line::kind::comment && kind != ini_line::kind::blank) {
      break;
    }
  }
  return i;
}

fn ini_file::set_header(std::string_view comment) -> void
{
  // Drop existing leading comment/blank block and replace with the new one.
  const usize end = header_end_index();
  m_lines.erase(m_lines.begin(),
                m_lines.begin() + static_cast<std::ptrdiff_t>(end));

  std::vector<std::unique_ptr<ini_line>> header;
  std::string_view view{comment};
  while (!view.empty()) {
    let nl = view.find('\n');
    let chunk = (nl == std::string_view::npos) ? view : view.substr(0, nl);
    header.push_back(std::make_unique<ini_comment>(std::string{chunk}));
    if (nl == std::string_view::npos) break;
    view.remove_prefix(nl + 1);
  }

  m_lines.insert(m_lines.begin(), std::make_move_iterator(header.begin()),
                 std::make_move_iterator(header.end()));
  m_dirty = true;
}

} // namespace oo
