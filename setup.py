"""
:copyright: (c) 2021 by Nightfall
:license: MIT, see LICENSE for more details.
"""
import os
import sys

from setuptools import setup
from setuptools.command.install import install


def readme():
    """Return long description from file."""
    with open('README.md') as f:
        return f.read()

setup(
    name="nightfall",
    version="0.2.0",
    description="Python SDK for Nightfall",
    long_description=readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/levlaz/nightfall-python-sdk",
    author="Nightfall",
    author_email="support@nightfall.ai",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet",
        "Programming Language :: Python :: 3 :: Only",
    ],
    keywords='nightfall dlp api sdk',
    packages=['nightfall'],
    install_requires=[
        'requests',
    ],
    python_requires='>=3.6.*'
)
