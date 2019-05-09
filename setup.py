# coding: utf-8

import sys
from setuptools import setup, find_packages

NAME = "af_lenz"
VERSION = "1.2.8"

#REQUIRES = ["autofocus"]
REQUIRES = ["autofocus-client-library", "requests"]

setup(
    name=NAME,
    version=VERSION,
    description="Autofocus Lenz",
    author_email="jwhite@paloaltonetworks.com",
    url="",
    keywords=["autofocus", "af_lenz"],
    install_requires=REQUIRES,
    packages=find_packages(),
    py_modules=['af_lenz'],
    include_package_data=True,
    long_description="A tool for interfacing with the PANW autofocus api",
    python_requires = ">3.4",
    entry_points = {
        'console_scripts': ['af_lenz=af_lenz:main']
    }
)
