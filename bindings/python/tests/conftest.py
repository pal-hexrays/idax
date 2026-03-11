"""Shared fixtures and CLI options for idax Python binding tests."""

import pytest
import os


def pytest_addoption(parser):
    parser.addoption(
        "--binary",
        action="store",
        default=None,
        help="Path to binary file for integration tests",
    )


@pytest.fixture(scope="session")
def binary_path(request):
    """Return the binary path from --binary, or skip if not provided."""
    path = request.config.getoption("--binary")
    if not path:
        pytest.skip("No --binary argument provided")
    return path


@pytest.fixture(scope="session")
def db(binary_path):
    """Open a database for integration tests. Closes on teardown."""
    import idax

    idax.database.init()
    idax.database.open(binary_path, True)
    idax.analysis.wait()
    yield idax
    idax.database.close(False)
