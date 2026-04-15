// Findings: severity enum, Finding struct, and parsers for each tool's output.

pub mod models;
pub mod parse;

pub use models::{Finding, Severity};
pub use parse::{extract_hosts_from_subfinder, parse_httpx_output, parse_nuclei_output};
