from skbuild import setup

setup(
    name="pycaracal",
    version="0.11.1",
    author="Maxime Mouchet",
    author_email="max@maxmouchet.com",
    url="https://github.com/dioptra-io/caracal",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: C++",
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
    ],
    python_requires=">=3.8",
    package_dir={"": "python"},
    packages=["pycaracal"],
    cmake_args=[
        "-DWITH_BINARY=OFF",
        "-DWITH_TESTS=OFF",
    ],
    cmake_install_dir="python/pycaracal",
)
