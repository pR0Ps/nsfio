from setuptools import setup, find_packages

setup(
    name="nsfio",
    version="0.0.0",
    description="Switch File I/O library",
    url="https://github.com/pR0Ps/nsfio",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "Topic :: Utilities",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ],
    install_requires=[
        "pycryptodome>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "nsfio = nsfio.__main__:main"
        ]
    },
    python_requires=">=3.7",
)
