from __future__ import annotations

from pytest import CaptureFixture

from albs_graph.cli import main


def test_top_level_help_lists_command_summaries(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["--help"])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Fetch an ALBS build by --build-id." in output
    assert "Show a focused RPM trust path." in output


def test_fetch_without_args_shows_help(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["fetch"])

    output = capsys.readouterr().out

    assert exit_code == 2
    assert "Usage:" in output
    assert "--build-id" in output


def test_trust_path_without_args_shows_help(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["trust-path"])

    output = capsys.readouterr().out

    assert exit_code == 2
    assert "Usage:" in output
    assert "--build-id" in output
    assert "--rpm" in output


def test_short_help_flag_is_supported(capsys: CaptureFixture[str]) -> None:
    exit_code = main(["fetch", "-h"])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Fetch an ALBS build by --build-id" in output
