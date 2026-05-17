from setuptools import setup, find_packages

setup(
    name="ibrovix-validator",
    version="2.0.0",
    description="High-performance proxy validation and filtering tool with Interactive TUI, Geo-IP, and SNI injection mapping",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="IBROVIX",
    url="https://github.com/IBROVIX1/ibrovix-validator",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "dev": ["pytest", "pytest-asyncio", "pytest-cov"],
        "geo": ["aiohttp"],
        "harvester": ["httpx>=0.25.0"],
    },
    entry_points={
        "console_scripts": [
            "ibrovix-validator=ibrovix_validator.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
