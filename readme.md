# Bitbucket Server API Wrapper
A simple wrapper for the Atlassian's Bitbucket Server / Bitbucket Datacenter (formerly Stash) REST API, written in Python.

[![Test](https://github.com/JoeStanleySEL/bitbucketserver/actions/workflows/test-and-coverage.yml/badge.svg?branch=master)](https://github.com/JoeStanleySEL/bitbucketserver/actions/workflows/test-and-coverage.yml)
![Coverage](https://raw.githubusercontent.com/JoeStanleySEL/bitbucketserver/coverage-badge/coverage.svg)

## Usage

### Instantiating

#### Basic Auth:

```python
import bitbucketserver
bb = bitbucketserver.BitbucketServer(
    url="http://mybitbucket.company.com",
    basic_auth=('username', 'password'))
```

#### Personal Tokens:

```python
bb = bitbucketserver.BitbucketServer(
    url="http://mybitbucket.company.com",
    bearer_token="...")
```


### Examples

```python
myrepo = bb.repo('project-key', 'my-repo')
commits = myrepo.commits()
new_repo = bb.create_new_repo('PROJ', "New Repo Name")
new_repo.set_group_permission("dev-team", "REPO_WRITE")
```


#### Object Internals

All `resource.BitbucketObject` subclasses' attributes are dynamically accessed directly from the JSON dictionary returned by the Bitbucket server stored in `obj._raw`.
Any key present in the `obj._raw` dictionary can be accessed with `obj.key`.


For example, the `slug` attribute for a repository is accessed either by
`repo.slug` or `repo._raw["slug"]`.

## Installation

Install the library using pip:

    pip install bitbucketserver

You may also clone the repository and run `setup.py` manually.

## Requirements
Requirements for the module should be installed automatically if installed via pip or setup.py.

### Requests
This module uses the Python library [Requests](http://docs.python-requests.org/en/master/) for communication. Install it with:

    pip install requests

Version 2.4.2 or greater is required.


## Development

### Testing
Tests are written using Python `unittest` and can be executed with the following command:

    python3 -m unittest discover .

To observe test-coverage, you may use the [`coverage.py`](https://coverage.readthedocs.io/en/latest/) tool with the following
command:

    python3 -m coverage --source ./bitbucketserver -m unittest discover .
