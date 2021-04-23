import sys
from pathlib import Path
from skbuild import setup

cmake_args = []

# If conan exists in the current Python installation,
# pass its path to CMake. This solves an issue where
# the cmake-conan module cannot find conan in some cases.
conan_cmd = Path(sys.executable).parent / "conan"
if conan_cmd.exists():
    cmake_args.append(f"-DCONAN_CMD={conan_cmd}")


setup(
    name="pycaracal",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    cmake_args=cmake_args,
)
