from skbuild import setup

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
    cmake_install_dir="python/pycaracal",
)
