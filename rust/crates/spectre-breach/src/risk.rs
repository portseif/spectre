//! Risk indicators and remediation derived from breach metadata.

use chrono::{Datelike, NaiveDate, Utc};
use spectre_core::model::{BreachIncident, RiskAssessment, RiskIndicator, RiskLevel};

const RECENT_YEARS: i32 = 3;

fn has_class(incident: &BreachIncident, needles: &[&str]) -> bool {
    incident.data_classes.iter().any(|class| {
        let lowered = class.to_ascii_lowercase();
        needles.iter().any(|needle| lowered.contains(needle))
    })
}

fn is_recent(incident: &BreachIncident, today: NaiveDate) -> bool {
    incident
        .breach_date
        .as_deref()
        .and_then(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").ok())
        .is_some_and(|date| today.year() - date.year() <= RECENT_YEARS)
}

/// Assess breach exposure for one account.
pub fn assess_risk(breaches: &[BreachIncident]) -> RiskAssessment {
    assess_risk_on(breaches, Utc::now().date_naive())
}

pub fn assess_risk_on(breaches: &[BreachIncident], today: NaiveDate) -> RiskAssessment {
    let mut indicators = Vec::new();
    let mut recommendations: Vec<&str> = Vec::new();
    let push = |recommendation: &'static str, list: &mut Vec<&str>| {
        if !list.contains(&recommendation) {
            list.push(recommendation);
        }
    };

    for incident in breaches.iter().filter(|incident| !incident.is_fabricated) {
        let label = &incident.title;
        if incident.is_stealer_log || incident.is_malware {
            indicators.push(RiskIndicator {
                title: format!("{label}: credentials captured by malware"),
                detail: "Data from information-stealing malware suggests a device used with this account was compromised.".into(),
                severity: RiskLevel::Critical,
            });
            push(
                "Scan devices used with this account for malware before changing passwords, then rotate every password used on them.",
                &mut recommendations,
            );
        }
        if incident.password_data_exposed {
            let recent = is_recent(incident, today);
            indicators.push(RiskIndicator {
                title: format!("{label}: password data exposed"),
                detail: format!(
                    "The breach{} contained password data in some form (often hashed). This does not prove a current password is known.",
                    incident.breach_date.as_deref().map(|date| format!(" ({date})")).unwrap_or_default()
                ),
                severity: if recent { RiskLevel::High } else { RiskLevel::Medium },
            });
            push("Change the password for each affected service and anywhere the same password was reused.", &mut recommendations);
            push("Use a password manager to give every account a unique, randomly generated password.", &mut recommendations);
        }
        if has_class(incident, &["security questions"]) {
            indicators.push(RiskIndicator {
                title: format!("{label}: security questions exposed"),
                detail: "Security question answers can be used for account recovery attacks.".into(),
                severity: RiskLevel::High,
            });
            push("Replace security-question answers with random values stored in a password manager.", &mut recommendations);
        }
        if has_class(incident, &["credit card", "bank account", "payment"]) {
            indicators.push(RiskIndicator {
                title: format!("{label}: financial data exposed"),
                detail: "Payment or banking details were part of the breach.".into(),
                severity: RiskLevel::High,
            });
            push("Review financial statements and consider replacing affected payment cards.", &mut recommendations);
        }
        if has_class(incident, &["government issued", "social security", "passport", "driver's licen"]) {
            indicators.push(RiskIndicator {
                title: format!("{label}: identity documents exposed"),
                detail: "Government identifiers increase identity-theft risk.".into(),
                severity: RiskLevel::High,
            });
            push("Consider a credit freeze and identity-theft monitoring.", &mut recommendations);
        }
        if incident.is_sensitive {
            indicators.push(RiskIndicator {
                title: format!("{label}: sensitive breach"),
                detail: "Exposure in this breach may itself be sensitive information.".into(),
                severity: RiskLevel::Medium,
            });
        }
        if has_class(incident, &["phone numbers", "physical addresses", "dates of birth"]) {
            indicators.push(RiskIndicator {
                title: format!("{label}: personal details exposed"),
                detail: "Contact and personal details enable targeted phishing and social engineering.".into(),
                severity: RiskLevel::Low,
            });
            push("Treat unexpected messages referencing these services with suspicion (targeted phishing).", &mut recommendations);
        }
        if incident.is_spam_list {
            indicators.push(RiskIndicator {
                title: format!("{label}: spam list"),
                detail: "The address appeared on a spam list; expect unsolicited mail.".into(),
                severity: RiskLevel::Low,
            });
        }
    }

    if !breaches.is_empty() {
        push("Enable multi-factor authentication on the email account and on affected services.", &mut recommendations);
    } else {
        push("No known breaches. Keep using unique passwords and multi-factor authentication.", &mut recommendations);
    }
    let level = indicators.iter().map(|indicator| indicator.severity).max().unwrap_or(if breaches.is_empty() {
        RiskLevel::None
    } else {
        RiskLevel::Low
    });
    indicators.sort_by(|left, right| right.severity.cmp(&left.severity));
    RiskAssessment { level, indicators, recommendations: recommendations.into_iter().map(str::to_string).collect() }
}
