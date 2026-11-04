"""The cloud CLI's two operator-facing promises, checked without starting a server.

A managed platform assigns the port and publishes it as `PORT`; a service that ignores it binds
somewhere the platform's proxy is not looking, so the deployment looks healthy from the outside and
answers nobody. The flag split for the worker jobs is the other half of the same problem: the brief
needs three separate start commands, and a start command that quietly ran the wrong job would page
nobody while still logging that it started.

These are unit tests over argument parsing and resolution. The behaviour behind the flags - what a
delivery-only tick actually does - is covered in `test_cloud_delivery.py`.
"""

from __future__ import annotations

import argparse

import pytest

from watchtower.cloud.cli import (
    DEFAULT_PORT,
    JOB_BOTH,
    JOB_CHOICES,
    _jobs,
    _resolve_port,
    build_parser,
)
from watchtower.cloud.config import CloudConfigError
from watchtower.cloud.worker import ALL_JOBS, DELIVERY, ESCALATION, select_jobs

ALL_INTERFACES = "0.0.0.0"  # noqa: S104 - an argument to argparse; nothing here binds a socket.


def parse(argv: list[str]) -> argparse.Namespace:
    return build_parser().parse_args(argv)


class TestPlatformPort:
    def test_the_port_the_platform_published_is_the_port_used(self):
        assert _resolve_port(None, {"PORT": "10000"}) == (10000, "PORT")

    def test_an_explicit_flag_beats_the_platform(self):
        # A local run against a port already taken is the reason `--port` still wins.
        assert _resolve_port(8081, {"PORT": "10000"}) == (8081, "--port")

    def test_no_port_anywhere_falls_back_to_the_documented_default(self):
        assert _resolve_port(None, {}) == (DEFAULT_PORT, "default")
        # Render and friends set the variable empty rather than absent sometimes.
        assert _resolve_port(None, {"PORT": "  "}) == (DEFAULT_PORT, "default")

    def test_a_port_that_is_not_a_number_refuses_to_start(self):
        with pytest.raises(CloudConfigError, match="not a port number"):
            _resolve_port(None, {"PORT": "tcp://8080"})

    def test_a_port_outside_the_valid_range_refuses_to_start(self):
        for published in ("0", "70000", "-1"):
            with pytest.raises(CloudConfigError, match="outside 1-65535"):
                _resolve_port(None, {"PORT": published})

    def test_the_failure_says_which_variable_is_wrong(self):
        # The operator reading this is standing in front of a platform console, not this file.
        with pytest.raises(CloudConfigError, match="PORT"):
            _resolve_port(None, {"PORT": "eighty"})

    def test_serve_leaves_the_port_to_the_platform_unless_told_otherwise(self):
        assert parse(["serve"]).port is None
        assert parse(["serve", "--port", "9000"]).port == 9000

    def test_serve_still_defaults_to_loopback(self):
        # The port became platform-supplied; the address deliberately did not. A default of
        # every-interface would turn every local run into a service reachable from the network.
        assert parse(["serve"]).host == "127.0.0.1"
        assert parse(["serve", "--host", ALL_INTERFACES]).host == ALL_INTERFACES


class TestJobSelection:
    def test_no_selection_means_every_job(self):
        assert select_jobs(None) == ALL_JOBS
        assert select_jobs([DELIVERY, ESCALATION]) == ALL_JOBS

    def test_one_job_alone_selects_one_job(self):
        assert select_jobs(DELIVERY) == frozenset({DELIVERY})
        assert select_jobs(ESCALATION) == frozenset({ESCALATION})
        assert select_jobs([ESCALATION]) == frozenset({ESCALATION})

    def test_a_comma_separated_list_is_the_same_set_however_it_is_spaced(self):
        assert select_jobs("delivery, escalation") == ALL_JOBS

    def test_an_unknown_job_is_refused_by_name(self):
        # A typo in a start command must not become a worker that logs a healthy start and then
        # does nothing forever.
        with pytest.raises(ValueError, match="unknown worker job"):
            select_jobs("delivry")

    def test_a_selection_that_is_empty_is_refused(self):
        for empty in ("", " ", ",", []):
            with pytest.raises(ValueError, match="at least one job"):
                select_jobs(empty)

    def test_worker_defaults_to_both_jobs(self):
        # Nothing that exists today passes --jobs, so the behaviour of every current start command
        # is unchanged.
        assert parse(["worker"]).jobs == JOB_BOTH
        assert _jobs(parse(["worker"])) is None

    def test_worker_takes_each_job_alone(self):
        assert _jobs(parse(["worker", "--jobs", "delivery"])) == DELIVERY
        assert _jobs(parse(["worker", "--jobs", "escalation"])) == ESCALATION

    def test_the_worker_refuses_a_job_the_loop_does_not_know(self):
        with pytest.raises(SystemExit):
            parse(["worker", "--jobs", "cleanup"])

    def test_the_cli_vocabulary_matches_the_loop(self):
        assert JOB_CHOICES[1:] == (DELIVERY, ESCALATION)


class TestSubcommandsStayPut:
    def test_every_command_the_deployment_docs_name_parses(self):
        assert parse(["serve", "--no-worker", "--host", ALL_INTERFACES]).no_worker is True
        assert parse(["verify"]).command == "verify"
        assert parse(["service-key"]).command == "service-key"

    def test_the_flag_split_the_three_process_deployment_needs_is_the_parser_we_ship(self):
        # These three lines are copied verbatim into render.yaml and docs/deployment.md; if the
        # parser ever stops accepting one, the deployment fails at start instead of at review.
        assert parse(["serve", "--no-worker", "--host", ALL_INTERFACES]).port is None
        assert parse(["worker", "--jobs", "delivery"]).jobs == "delivery"
        assert parse(["worker", "--jobs", "escalation"]).jobs == "escalation"
