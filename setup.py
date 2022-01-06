from setuptools import setup, find_packages


def readme():
    """Return long description from file."""
    with open('README.md') as f:
        return f.read()


setup(
    name="nightfall",
    version="1.3.0",
    description="Python SDK for Nightfall",
    long_description=readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/nightfallai/nightfall-python-sdk",
    author="Nightfall",
    author_email="support@nightfall.ai",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
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
    packages=find_packages(exclude=['tests*']),
    install_requires=[
        'requests',
        'urllib3'
    ],
    python_requires='>=3.7.*'
)
