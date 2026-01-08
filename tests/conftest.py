
import pytest
import sys
from unittest.mock import MagicMock

# Mock curses completely to avoid import errors on Windows and TUI interference
mock_curses_module = MagicMock()
mock_curses_module.wrapper = MagicMock(side_effect=lambda func, *args: func(MagicMock(), *args))
sys.modules["curses"] = mock_curses_module

@pytest.fixture(autouse=True)
def mock_root_check(mocker):
    """Always pretend to be root."""
    mocker.patch("os.geteuid", return_value=0, create=True)

@pytest.fixture
def mock_subproc(mocker):
    """Mock subprocess.run to avoid actual execution."""
    mock_run = mocker.patch("subprocess.run")
    # Default behavior: return success with empty output
    mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
    return mock_run

@pytest.fixture
def mock_fs(mocker):
    """Mock filesystem writing operations."""
    mocker.patch("pathlib.Path.write_text")
    mocker.patch("pathlib.Path.mkdir")
    mocker.patch("os.chmod")
    mocker.patch("os.umask", return_value=0o022)
    mocker.patch("builtins.print")  # Silence prints

@pytest.fixture
def mock_curses(mocker):
    """Mock curses to avoid TUI errors."""
    mock_curses = mocker.patch("curses.wrapper")
    mocker.patch("curses.initscr")
    mocker.patch("curses.noecho")
    mocker.patch("curses.cbreak")
    mocker.patch("curses.start_color")
    mocker.patch("curses.init_pair")
    mocker.patch("curses.color_pair")
    mocker.patch("curses.endwin")
    # Also patch the CursesUI class in tui module if needed, 
    # but initially patching the low-level curses might be enough 
    # if we interact via the CursesUI mock in the test.
    return mock_curses
