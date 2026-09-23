//! What platforms owe, month by month.
//!
//! The price list is a plan, not a tip jar: each platform (customer) pays a monthly fee that
//! includes a bundle of agreements and trust lookups, then a small metered price beyond it,
//! plus a flat fee per dispute that escalates to a jury or arbiter — the one unit of real work.
//!
//! The monthly fee is also an anti-gaming control, not just revenue. A trust score that needs
//! history from several *independent platforms* (see store.rs) is only as strong as the cost of
//! faking a platform, and every platform is an operator-issued key with a recurring price on it.
//!
//! Money is kept in **mills** (1/1000 of a US dollar) as integers, so a $0.001 lookup is exactly
//! 1 and nothing is ever rounded by floating point.

use std::collections::BTreeMap;

use crate::json::Json;

/// The price list. Every field can be overridden from the environment at boot (see
/// `Pricing::from_env`), so changing a price never needs a code change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pricing {
    pub monthly_mills: i64,
    pub included_agreements: u64,
    pub agreement_mills: i64,
    pub dispute_mills: i64,
    pub included_lookups: u64,
    pub lookup_mills: i64,
}

impl Default for Pricing {
    fn default() -> Pricing {
        Pricing {
            monthly_mills: 29_000,  // $29 / month per platform
            included_agreements: 500,
            agreement_mills: 20,    // $0.02 each after that
            dispute_mills: 500,     // $0.50 per escalated dispute
            included_lookups: 10_000,
            lookup_mills: 1,        // $0.001 each after that
        }
    }
}

impl Pricing {
    pub fn from_env() -> Pricing {
        let d = Pricing::default();
        let dollars = |name: &str, default: i64| -> i64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|v| v.is_finite() && *v >= 0.0)
                .map(|v| (v * 1000.0).round() as i64)
                .unwrap_or(default)
        };
        let count = |name: &str, default: u64| -> u64 {
            std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
        };
        Pricing {
            monthly_mills: dollars("PRICE_MONTHLY_USD", d.monthly_mills),
            included_agreements: count("INCLUDED_AGREEMENTS", d.included_agreements),
            agreement_mills: dollars("PRICE_AGREEMENT_USD", d.agreement_mills),
            dispute_mills: dollars("PRICE_DISPUTE_USD", d.dispute_mills),
            included_lookups: count("INCLUDED_LOOKUPS", d.included_lookups),
            lookup_mills: dollars("PRICE_LOOKUP_USD", d.lookup_mills),
        }
    }

    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("monthly_usd", usd(self.monthly_mills)),
            ("included_agreements", Json::num(self.included_agreements as f64)),
            ("agreement_usd", usd(self.agreement_mills)),
            ("dispute_usd", usd(self.dispute_mills)),
            ("included_lookups", Json::num(self.included_lookups as f64)),
            ("lookup_usd", usd(self.lookup_mills)),
            ("public_lookups", Json::str("free without a key, limited per IP address")),
        ])
    }
}

/// Mills as a dollar amount, for display. Display only — sums are always done in mills.
pub fn usd(mills: i64) -> Json {
    Json::num(mills as f64 / 1000.0)
}

/// One month's metered usage.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    pub agreements: u64,
    pub disputes: u64,
    pub lookups: u64,
}

impl Usage {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("agreements", Json::num(self.agreements as f64)),
            ("disputes", Json::num(self.disputes as f64)),
            ("lookups", Json::num(self.lookups as f64)),
        ])
    }

    pub fn from_json(j: &Json) -> Usage {
        let n = |k: &str| j.get(k).and_then(|v| v.as_f()).unwrap_or(0.0) as u64;
        Usage { agreements: n("agreements"), disputes: n("disputes"), lookups: n("lookups") }
    }
}

/// One line of an invoice.
pub struct Line {
    pub what: String,
    pub mills: i64,
}

/// A month's bill: the plan fee, then anything over the included bundle.
pub fn invoice(p: &Pricing, u: &Usage) -> Vec<Line> {
    let mut lines = vec![Line { what: "Platform plan".into(), mills: p.monthly_mills }];
    let extra_agreements = u.agreements.saturating_sub(p.included_agreements);
    if extra_agreements > 0 {
        lines.push(Line {
            what: format!("{extra_agreements} agreements over the {} included", p.included_agreements),
            mills: extra_agreements as i64 * p.agreement_mills,
        });
    }
    if u.disputes > 0 {
        lines.push(Line { what: format!("{} escalated disputes", u.disputes), mills: u.disputes as i64 * p.dispute_mills });
    }
    let extra_lookups = u.lookups.saturating_sub(p.included_lookups);
    if extra_lookups > 0 {
        lines.push(Line {
            what: format!("{extra_lookups} trust lookups over the {} included", p.included_lookups),
            mills: extra_lookups as i64 * p.lookup_mills,
        });
    }
    lines
}

pub fn total(lines: &[Line]) -> i64 {
    lines.iter().map(|l| l.mills).sum()
}

pub fn invoice_json(month: &str, lines: &[Line], usage: &Usage) -> Json {
    Json::obj(vec![
        ("month", Json::str(month)),
        ("usage", usage.to_json()),
        (
            "lines",
            Json::Array(
                lines
                    .iter()
                    .map(|l| Json::obj(vec![("item", Json::str(l.what.clone())), ("usd", usd(l.mills))]))
                    .collect(),
            ),
        ),
        ("total_usd", usd(total(lines))),
    ])
}

/// A payment the operator received, recorded by hand (a Stripe charge id, a USDC tx hash).
#[derive(Debug, Clone, PartialEq)]
pub struct Payment {
    pub mills: i64,
    pub reference: String,
    pub at_ms: i64,
}

/// "YYYY-MM" for a unix-ms timestamp, in UTC.
pub fn month_of(ms: i64) -> String {
    let (y, m, _) = civil_from_days(ms.div_euclid(86_400_000));
    format!("{y:04}-{m:02}")
}

/// Every month from `from` through `to` inclusive, as "YYYY-MM".
pub fn months_between(from_ms: i64, to_ms: i64) -> Vec<String> {
    let (mut y, mut m, _) = civil_from_days(from_ms.div_euclid(86_400_000));
    let (ty, tm, _) = civil_from_days(to_ms.div_euclid(86_400_000));
    let mut out = Vec::new();
    while (y, m) <= (ty, tm) && out.len() < 1200 {
        out.push(format!("{y:04}-{m:02}"));
        m += 1;
        if m > 12 {
            m = 1;
            y += 1;
        }
    }
    out
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// Per-month usage, keyed "YYYY-MM" so iteration is in date order.
pub type UsageByMonth = BTreeMap<String, Usage>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_convert_correctly_across_boundaries() {
        assert_eq!(month_of(0), "1970-01");
        assert_eq!(civil_from_days(19_782), (2024, 2, 29)); // leap day
        assert_eq!(month_of(1_790_188_806_916), "2026-09");
        let jan = 1_767_225_600_000; // 2026-01-01T00:00:00Z
        assert_eq!(month_of(jan - 1), "2025-12");
        assert_eq!(month_of(jan), "2026-01");
        assert_eq!(months_between(jan - 1, jan + 40 * 86_400_000), vec!["2025-12", "2026-01", "2026-02"]);
    }

    #[test]
    fn a_quiet_month_is_just_the_plan_and_overage_is_metered() {
        let p = Pricing::default();
        assert_eq!(total(&invoice(&p, &Usage::default())), 29_000);
        let busy = Usage { agreements: 600, disputes: 3, lookups: 12_500 };
        // $29 + 100 × $0.02 + 3 × $0.50 + 2,500 × $0.001 = $35.00
        assert_eq!(total(&invoice(&p, &busy)), 29_000 + 2_000 + 1_500 + 2_500);
    }
}
