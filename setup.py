"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

Setup BitbucketServer

Install script for installing the BitbucketServer API wrapper.

"""
from setuptools import setup, find_packages
VERSION = '1.0.0' # also located in bitbucketserver/__init__.py

REQUIRED_PACKAGES = ['requests>=2.4.2']
TEST_PACKAGES = ['unittest']

setup(
    name='bitbucketserver',
    description="Wrapper for the Stash/Bitbucket Server REST API.",
    url="https://github.com/Schweitzer-Engineering-Laboratories/bitbucketserver",
    version=VERSION,
    packages=find_packages(exclude=['unittests']),
    author='Jason Kemp',
    author_email='jason_kemp@selinc.com',
    python_requires='>=3.6',
    install_requires=REQUIRED_PACKAGES,
    tests_require=TEST_PACKAGES,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Intended Audience :: Developers',
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: BSD License',
        'Topic :: Software Development :: Version Control :: Git',
        'Topic :: Utilities'
    ]
)
