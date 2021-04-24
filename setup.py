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
    author="Maxime Mouchet",
    author_email="max@maxmouchet.com",
    url="https://github.com/dioptra-io/caracal",
    classifiers=[
        "Programming Language :: C++",
        "Programming Language :: Python :: 3",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
    ],
    use_scm_version=True,
    python_requires=">=3.8",
    setup_requires=["setuptools_scm"],
    package_dir={"": "python"},
    packages=["pycaracal"],
    cmake_args=cmake_args,
    cmake_install_dir="python/pycaracal",
)
