#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="nessus-tool",
    version="1.0.0",
    description="Tool for downloading Nessus scans, creating scans, and converting .nessus files to Excel/CSV",
    author="jasonhillva",
    packages=find_packages(),
    py_modules=["nessus_client", "nessus_parser", "nessus_downloader", "nessus_converter", "nessus_tool", "web_app"],
    install_requires=[
        "pandas>=1.0.0",
        "openpyxl>=3.0.0",
        "requests>=2.0.0",
        "flask>=2.0.0",  # Added Flask for web interface
    ],
    entry_points={
        'console_scripts': [
            'nessus-tool=nessus_tool:main',
        ],
    },
    python_requires='>=3.6',
    include_package_data=True,
    package_data={
        '': ['templates/*.html'],
    },
)