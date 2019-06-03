import pytest


PROFILE_CI="ci"
PROFILE_DEVEL="devel"


def pytest_addoption(parser):
    parser.addoption(
        "--profile",
        default=PROFILE_CI,
        choices=[PROFILE_CI, PROFILE_DEVEL],
        help="Profile for running the test: {} or {}".format(
            PROFILE_CI,
            PROFILE_DEVEL
        )
    )


@pytest.fixture
def profile(request):
    return request.config.getoption("--profile")


# This is used for defining global variables in pytest.
def pytest_configure():
    pytest.profile_ci = PROFILE_CI
    pytest.profile_devel = PROFILE_DEVEL
