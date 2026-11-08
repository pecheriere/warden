//! Tests for the format helpers: times, byte counts and durations as the pages
//! show them.

use super::super::format::{bytes, clock, idle_label, secs_label, utc_parts};

#[test]
fn idle_time_reads_in_the_largest_fitting_units() {
    for (secs, shown) in [
        (0, "Active now"),
        (4, "Active now"),
        (5, "Idle 5 s"),
        (59, "Idle 59 s"),
        (60, "Idle 1 min"),
        (3_599, "Idle 59 min"),
        (3_600, "Idle 1 h"),
        (3_659, "Idle 1 h"),
        (3_660, "Idle 1 h 1 min"),
        (86_400, "Idle 24 h"),
    ] {
        assert_eq!(idle_label(secs), shown, "{secs}");
    }
}

#[test]
fn formats_utc_timestamps() {
    let utc = |ts| {
        let (date, time) = utc_parts(ts);
        format!("{date} {time}")
    };
    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(1_800_000_000), "2027-01-15 08:00:00 UTC");
    assert_eq!(utc(951_825_600), "2000-02-29 12:00:00 UTC");
    assert_eq!(utc(1_709_208_000), "2024-02-29 12:00:00 UTC");
    assert_eq!(utc(4_102_444_799), "2099-12-31 23:59:59 UTC");
    assert_eq!(utc(-1), "1969-12-31 23:59:59 UTC");
}

#[test]
fn clock_is_utc_with_a_machine_readable_time() {
    assert_eq!(
        clock(1_800_000_065).into_string(),
        r#"<time datetime="2027-01-15T08:01:05Z">08:01 UTC</time>"#
    );
    assert_eq!(
        clock(-1).into_string(),
        r#"<time datetime="1969-12-31T23:59:59Z">23:59 UTC</time>"#
    );
}

#[test]
fn formats_byte_counts() {
    for (n, text) in [
        (0, "0 B"),
        (999, "999 B"),
        (1_000, "1.0 KB"),
        (1_299, "1.2 KB"),
        (999_999, "999.9 KB"),
        (1_000_000, "1.0 MB"),
        (3_456_789, "3.4 MB"),
        (12_345_678_901, "12345.6 MB"),
        (u64::MAX, "18446744073709.5 MB"),
    ] {
        assert_eq!(bytes(n), text, "{n}");
    }
}

#[test]
fn labels_granted_windows() {
    assert_eq!(secs_label(900), "15m");
    assert_eq!(secs_label(14_400), "4h");
    assert_eq!(secs_label(901), "901s");
    assert_eq!(secs_label(-5), "-5s");
}
