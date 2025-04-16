#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="nessus-tool",
    version="1.0.0",
    description="Tool for downloading Nessus scans and converting .nessus files to Excel/CSV",
    author="jasonhillva",
    packages=find_packages(),
    py_modules=["nessus_client", "nessus_parser", "nessus_downloader", "nessus_converter", "nessus_tool"],
    install_requires=[
        "pandas>=1.0.0",
        "openpyxl>=3.0.0",
        "requests>=2.0.0",
    ],
    entry_points={
        'console_scripts': [
            'nessus-tool=nessus_tool:main',
        ],
    },
    python_requires='>=3.6',
)