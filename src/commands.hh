#include "cli.hh"
#include "common.hh"
#include "linux_namespace.hh"

namespace oo {

fn up(cli::cli &&cli) -> error_or<ok>;
fn down(cli::cli &&cli) -> error_or<ok>;
fn exec(cli::cli &&cli) -> error_or<ok>;
fn init(cli::cli &&cli) -> error_or<ok>;

// Cleanup helper: removes network interfaces, frees IP, removes namespace
// directory
fn cleanup_namespace(linux_namespace &ns, u8 subnet_octet,
                     std::string_view veth_host) -> void;

} // namespace oo
