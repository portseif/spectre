//! CSV export of findings.

use spectre_core::model::{Finding, InvestigationDetail};

/// Escape a CSV cell (RFC 4180) and neutralize spreadsheet formula injection
/// by prefixing cells that start with `= + - @` or control characters.
fn cell(value: &str) -> String {
    let neutralized = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value.to_string() };
    if neutralized.contains([',', '"', '\n', '\r']) { format!("\"{}\"", neutralized.replace('"', "\"\"")) } else { neutralized }
}

fn row(finding: &Finding) -> String {
    let sources: Vec<&str> = finding.sources.iter().filter_map(|source| source.url.as_deref()).collect();
    [
        finding.id.to_string(),
        finding.kind().as_str().to_string(),
        finding.provider_id.clone(),
        finding.title.clone(),
        finding.summary.clone().unwrap_or_default(),
        finding.confidence.category.label().to_string(),
        format!("{:.3}", finding.confidence.score),
        finding.verification_status.as_str().to_string(),
        finding.discovered_at.to_rfc3339(),
        sources.join(" "),
    ]
    .iter()
    .map(|value| cell(value))
    .collect::<Vec<_>>()
    .join(",")
}

pub fn findings_csv(detail: &InvestigationDetail) -> String {
    let mut output = String::from(
        "finding_id,kind,provider,title,summary,confidence_category,evidence_score,verification_status,discovered_at,sources\n",
    );
    for finding in &detail.findings {
        output.push_str(&row(finding));
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::cell;

    #[test]
    fn escapes_and_neutralizes() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(cell("-1"), "'-1");
    }
}
