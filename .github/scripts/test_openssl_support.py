"""Tests for openssl_support.py."""

import unittest
from datetime import date

from openssl_support import (
    PIN_FILE,
    PINNED_FLAG,
    SHIPPING_BUILDS,
    CheckError,
    has_openssl_src,
    newest_of_line,
    parse_pin,
    support_problem,
)

ENDS = date(2030, 4, 8)


class ParsePin(unittest.TestCase):
    """Tests for parse_pin."""

    def test_reads_the_settings(self) -> None:
        """A valid file gives the version and the date."""
        text = "# comment\nWARDEN_OPENSSL_VERSION=3.5.9\nWARDEN_OPENSSL_SUPPORT_ENDS=2030-04-08\n"
        self.assertEqual(parse_pin(text), ((3, 5, 9), ENDS))

    def test_reads_the_real_file(self) -> None:
        """The pin in the repository parses."""
        parse_pin(PIN_FILE.read_text(encoding="utf-8"))

    def test_refuses_a_missing_or_bad_setting(self) -> None:
        """A missing or malformed setting is an error, not a pass."""
        for text in (
            "",
            "WARDEN_OPENSSL_VERSION=3.5.9\n",
            "WARDEN_OPENSSL_SUPPORT_ENDS=2030-04-08\n",
            "WARDEN_OPENSSL_VERSION=3.5\nWARDEN_OPENSSL_SUPPORT_ENDS=2030-04-08\n",
            "WARDEN_OPENSSL_VERSION=3.5.9\nWARDEN_OPENSSL_SUPPORT_ENDS=soon\n",
        ):
            with self.subTest(text=text), self.assertRaises(CheckError):
                parse_pin(text)


class SupportProblem(unittest.TestCase):
    """Tests for support_problem."""

    def test_quiet_long_before_the_end(self) -> None:
        """Nothing to say while the end is far off."""
        self.assertEqual(support_problem(ENDS, date(2030, 1, 7), nightly=True), (False, None))

    def test_warns_before_the_end_and_fails_only_at_night(self) -> None:
        """Near the end, pull requests get a warning and the nightly run fails."""
        day = date(2030, 1, 8)
        self.assertFalse(support_problem(ENDS, day, nightly=False)[0])
        self.assertIsNotNone(support_problem(ENDS, day, nightly=False)[1])
        self.assertTrue(support_problem(ENDS, day, nightly=True)[0])

    def test_fails_from_the_end_on(self) -> None:
        """From the end date on, every run fails."""
        for day in (ENDS, date(2031, 1, 1)):
            with self.subTest(day=day):
                self.assertTrue(support_problem(ENDS, day, nightly=False)[0])


class NewestOfLine(unittest.TestCase):
    """Tests for newest_of_line."""

    def test_takes_the_highest_as_a_number_and_ignores_the_rest(self) -> None:
        """Versions compare as numbers, and other lines and betas do not count."""
        output = (
            "aaa\trefs/tags/openssl-3.5.9\n"
            "bbb\trefs/tags/openssl-3.5.10\n"
            "ccc\trefs/tags/openssl-3.5.11-beta1\n"
            "ddd\trefs/tags/openssl-3.6.5\n"
        )
        self.assertEqual(newest_of_line(output, (3, 5)), (3, 5, 10))

    def test_no_release_gives_nothing(self) -> None:
        """No matching tag gives no version."""
        self.assertIsNone(newest_of_line("", (3, 5)))


class ShippingBuilds(unittest.TestCase):
    """Tests for the builds that must ask for the pinned OpenSSL."""

    def test_each_sets_the_flag(self) -> None:
        """The Dockerfile and the packaging script both refuse another OpenSSL."""
        for build in SHIPPING_BUILDS:
            with self.subTest(build=build.name):
                self.assertIn(PINNED_FLAG, build.read_text(encoding="utf-8"))


class OpensslSrc(unittest.TestCase):
    """Tests for has_openssl_src."""

    def test_finds_the_package(self) -> None:
        """Only the exact package name counts."""
        self.assertTrue(has_openssl_src('[[package]]\nname = "openssl-src"\n'))
        self.assertFalse(has_openssl_src('[[package]]\nname = "openssl-sys"\n'))


if __name__ == "__main__":
    unittest.main()
