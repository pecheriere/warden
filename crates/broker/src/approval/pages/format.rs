//! Times, byte counts and durations as the pages show them.

use maud::{Markup, html};
use warden_broker_proto::Window;

use super::WINDOWS;
use crate::requests::window_label;

/// A time of day for Unix seconds `ts`: `HH:MM UTC`, which `warden.js`
/// replaces with the viewer's local time from `datetime`.
pub(super) fn clock(ts: i64) -> Markup {
    let [year, month, day, hour, minute, second] = utc_fields(ts);
    html! {
        time datetime=(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")) {
            (format!("{hour:02}:{minute:02} UTC"))
        }
    }
}

/// A byte count for people: `999 B`, `1.2 KB`, `3.4 MB` (powers of 1000,
/// rounded down to a tenth). `bytes` in `warden.js` is the same function.
pub(super) fn bytes(n: u64) -> String {
    match n {
        0..1_000 => format!("{n} B"),
        1_000..1_000_000 => {
            let tenths = n / 100;
            format!("{}.{} KB", tenths / 10, tenths % 10)
        }
        _ => {
            let tenths = n / 100_000;
            format!("{}.{} MB", tenths / 10, tenths % 10)
        }
    }
}

/// How long a session has been quiet, for people: `Active now` under 5 s (the
/// page refreshes every 5 s), then `Idle 12 s`, `Idle 4 min`, `Idle 2 h 5 min`,
/// rounded down. `idleLabel` in `warden.js` is the same function.
pub(super) fn idle_label(secs: u64) -> String {
    match secs {
        0..5 => "Active now".to_owned(),
        5..60 => format!("Idle {secs} s"),
        60..3_600 => format!("Idle {} min", secs / 60),
        _ if secs % 3_600 < 60 => format!("Idle {} h", secs / 3_600),
        _ => format!("Idle {} h {} min", secs / 3_600, secs % 3_600 / 60),
    }
}

/// A granted window length in words (`15m`, …), or seconds if unusual.
pub(super) fn secs_label(secs: i64) -> String {
    WINDOWS
        .into_iter()
        .chain(Window::COMMIT_SIGNING)
        .find(|w| u64::try_from(secs).is_ok_and(|s| s == w.secs()))
        .map_or_else(|| format!("{secs}s"), |w| window_label(w).to_owned())
}

/// `YYYY-MM-DD` and `HH:MM:SS UTC` for Unix seconds `ts`, so a narrow
/// column can break between them and nowhere else.
pub(super) fn utc_parts(ts: i64) -> (String, String) {
    let [year, month, day, hour, minute, second] = utc_fields(ts);
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!("{hour:02}:{minute:02}:{second:02} UTC"),
    )
}

/// Year, month, day, hour, minute and second (UTC) of Unix seconds `ts`.
const fn utc_fields(ts: i64) -> [i64; 6] {
    let secs = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(ts.div_euclid(86_400));
    [year, month, day, secs / 3600, secs % 3600 / 60, secs % 60]
}

/// Proleptic Gregorian date of the day `days` after 1970-01-01 (Howard
/// Hinnant's `civil_from_days`).
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}
