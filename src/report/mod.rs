// Markdown report rendering. JSON findings are serialized directly from
// RunRecord via serde; the markdown is templated here.

pub mod generator;

pub use generator::render_report;
