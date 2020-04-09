from setuptools import setup, find_packages

setup(
    name="filtercascade",
    version="0.4.0",
    description="A simple bloom filter cascade implementation in Python",
    long_description="A bloom filter cascade implementation in Python using the 32-bit variant of murmurhash3.",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Programming Language :: Python :: 3",
    ],
    keywords="bloom filter cascade multi level mlbf",
    url="https://github.com/mozilla/filter-cascade",
    project_urls={
        "Rust Project": "https://github.com/mozilla/rust-cascade",
        "Source": "https://github.com/mozilla/filter-cascade",
        "Tracker": "https://github.com/mozilla/filter-cascade/issues",
    },
    author="Mark Goodwin",
    author_email="mgoodwin@mozilla.com",
    license="Mozilla Public License 2.0 (MPL 2.0)",
    packages=["filtercascade"],
    install_requires=["bitarray>=0.9.2", "mmh3>=2.5.1",],
    include_package_data=True,
    zip_safe=False,
)
