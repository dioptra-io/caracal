import sys
from pathlib import Path
from skbuild import setup

# Find conan relatively to the current Python installation.
# This is required (for now) for isolated builds.
conan_cmd = Path(sys.executable).parent / "conan"

setup(
    name="pycaracal",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    cmake_args=[f"-DCONAN_CMD={conan_cmd}"],
)
