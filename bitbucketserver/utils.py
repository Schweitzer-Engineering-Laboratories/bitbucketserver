"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

utils.py

Utilities for using the library.
"""
import json

from bitbucketserver.resources import BitbucketObject
from bitbucketserver.resources import translate_timestamp

class BitbucketJsonEncoder(json.JSONEncoder):
    """JSON Encoder for Bitbucket objects.

    Usage:
        json.dump(bitbucket_object, fp, cls=BitbucketJsonEncoder)
    """

    def default(self, obj):
        if isinstance(obj, BitbucketObject):
            return obj._raw
        else:
            return super(type(self), self).default(obj)
