"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

connection.py

Defines the connection object for connecting to Bitbucket.
"""
import logging
from urllib.parse import urljoin

import requests

from bitbucketserver.resources import BitbucketAttribute

log = logging.getLogger(__name__)


DEFAULT_PAGE_LIMIT = 500 # default number of records to request in a paged request


class BitbucketServerException(Exception):
    """Bitbucket Server exceptions."""

    def __init__(self, errors, response=None, original_exception=None):
        """Create a Bitbucketserver exception object.

        Args:
            errors (list): list of errors
            response (requests.Response, optional): Defaults to None. The original Response object.
            original_exception (requests.HTTPError, optional): Defaults to None. The original HTTP Error.
        """
        if not errors:
            errors = []
        if errors:
            msg = errors[0]['message']
        else:
            msg = str(response)
        super(BitbucketServerException, self).__init__(msg)
        self.errors = errors
        self.response = response
        self.original_exception = original_exception


class BitbucketConnection(object):
    """Base connection object; this should be subclassed only."""

    def __init__(self, url, api_versions,
            bearer_token=None,
            basic_auth=None,
            headers=None,
            verify=True):
        """Create a base connection object.

        Args:
            url: full URL to the server
            api_versions: the API version to use by default
            verify (optional bool): verify certificates

        """
        self.url = url
        self.username = None
        self._headers = headers if headers else {}
        self.__basic_auth = basic_auth
        if self.__basic_auth:
            self.username = self.__basic_auth[0]
        self.__bearer_token = bearer_token
        self.verify = verify # certificate verifications
        self.page_limit = DEFAULT_PAGE_LIMIT
        self._api_versions = api_versions
        self._default_base = api_versions.core
        self._session = None
        self.last_response = None

    def __del__(self):
        # sometimes requests doesn't release the SSL socket at the end
        self.close()

    @property
    def session(self):
        if self._session is None:
            self._session = requests.Session()
            if self.__bearer_token is not None:
                self._session.headers['Authorization'] = "Bearer {0}".format(self.__bearer_token)
            if self.__basic_auth is not None:
                self._session.auth = self.__basic_auth
            self._session.verify = self.verify
            self._session.headers.update(self._headers)
        return self._session

    def close(self):
        if self._session:
            self._session.close()
            self._session = None

    def test(self):
        """Test the connection and credentials to the server.

        Returns:
            bool: True or False if the connection is working.
        """
        ret = False
        try:
            self.get('profile/recent/repos')
            ret = True
        except:
            pass
        return ret

    def get(self, uri, parameters=None, base=None):
        """Perform an HTTP GET request.

        Args:
            uri (str): the uri to GET from
            parameters (dict): additional URL parameters to add to the request
            base (str): the API base/version info. Use to access plugin API calls.
                Defaults to self._default_base.

        Returns:
            resources.BitbucketAttribute: dictionary of given content

        Raises:
            HTTPError: if there is an error response.
        """
        response = self.get_response(uri, parameters, base)
        raise_for_errors(response)
        return decode_json(response)

    def get_response(self, uri, parameters=None, base=None):
        """Perform an HTTP GET request, without error or JSON processing.

        Args:
            uri (str): the uri to GET from
            parameters (dict): additional URL parameters to add to the request
            base (str): the API base/version info. Use to access plugin API calls.
                Defaults to self._default_base.

        Returns:
            requests.Response: the response object
        """
        if base is None:
            base = self._default_base
        path = urljoin(base, uri)
        args = {'url': urljoin(self.url, path)}
        log.debug("GET request: " + path)
        if parameters:
            args['params'] = parameters
        response = self.session.get(**args)
        self.last_response = response
        return response

    def get_paged(self, uri, parameters=None, base=None, key='values',
        break_point=None):
        """Get all responses that come in a paged manner.

        Args:
            uri (str): the uri to GET from
            parameters (dict): additional URL parameters to add to the request
            base (str): the API base/version info. Use to access plugin API calls.
                Defaults to self._default_base.
            key (str): The specific key to look for in the paged results.
                The majority of paged requests use the 'values' key.
                A few, like file contents, use 'lines'.
            break_point (int): approximate number of records to retrieve.
                The loop will break if the retrieved records exceeds this number.
        Returns:
            list: list of dictionaries of returned values

        Raises:
            HTTPError: if there is an error response.
        """
        # Build first request:
        if parameters is None:
            parameters = {}
        values = []
        parameters['start'] = 0
        parameters['limit'] = self.page_limit
        while True:
            # Parse request
            content = self.get(uri, parameters, base=base)
            if not content:
                break
            values.extend(content[key])
            log.debug("retrieved entries: {0}".format(len(values)))
            # Continue...?
            if content['isLastPage']:
                break
            if break_point is not None and len(values) >= break_point:
                break
            # Build next request:
            else:
                try:
                    parameters['start'] = content['nextPageStart']
                except KeyError:
                    # because /browse doesn't give us nextPageStart...
                    parameters['start'] = content['size'] + content['start'] + 1
        return values

    def post(self, uri, parameters=None, content=None, json=None, files=None, headers=None, base=None):
        """Perform an HTTP POST request.

        Args:
            uri (str): the uri to POST to
            parameters (dict): additional URL parameters to add to the request
            content (str): content to be POSTed to the URI.
            json (dict): dictionary of content to be POSTed to the URI.
            files: list or dict passed directly to requests' post
                Typically a list of tuples.
            headers (dict): additional header attributes for this request only
            base (str): the API base/version info. Use to access plugin API calls.
                Defaults to self._default_base.

        Returns:
            requests.Response: an HTTP response object.

        Raises:
            HTTPError: if there is an error response.
        """
        if base is None:
            base = self._default_base
        path = urljoin(base, uri)
        log.debug("POST request: " + path)
        args = {'url': urljoin(self.url, path)}
        if content:
            args['data'] = content
        if json:
            args['json'] = json
        if parameters:
            args['params'] = parameters
        if files:
            args['files'] = files
        if headers:
            args['headers'] = headers
        response = self.session.post(**args)
        self.last_response = response
        raise_for_errors(response)
        return response

    def put(self, uri, parameters=None, content=None, json=None, base=None):
        """Perform an HTTP PUT request.

        Args:
            uri (str): the uri to PUT to
            content (str): content to be PUT to the URI.
            json (dict): dictionary of content to be PUT to the URI.
            base (str): the API base/version info. Use to access plugin API calls.
                Defaults to self._default_base.

        Returns:
            requests.Response: an HTTP response object.

        Raises:
            HTTPError: if there is an error response.
        """
        if base is None:
            base = self._default_base
        path = urljoin(base, uri)
        log.debug("PUT request %s", path)
        args = {'url': urljoin(self.url, path)}
        if content:
            args['data'] = content
        if json:
            args['json'] = json
        if parameters:
            args['params'] = parameters
        response = self.session.put(**args)
        self.last_response = response
        raise_for_errors(response)
        return response

    def delete(self, uri, parameters=None, content=None, json=None, base=None):
        """Perform an HTTP DELETE request.

        Args:
            uri (str): the uri to DELETE
            content (str): content to go with the DELETE request
            json (dict): content in dictionary form
            base (str): the API base/version info. Use to access plugin API calls.
                Defaults to self._default_base.

        Returns:
            requests.Response: an HTTP response object.

        Raises:
            HTTPError: if there is an error response.
        """
        if base is None:
            base = self._default_base
        path = urljoin(base, uri)
        log.debug("DELETE request %s", path)
        args = {'url': urljoin(self.url, path)}
        if content:
            args['data'] = content
        if json:
            args['json'] = json
        if parameters:
            args['params'] = parameters
        response = self.session.delete(**args)
        self.last_response = response
        raise_for_errors(response)
        return response


def decode_json(response):
    """Marshal the response JSON into a BitbucketAttribute object.

    Args:
        response (requests.Response): the incoming response

    Returns:
        BitbucketAttribute
    """
    return response.json(object_hook=BitbucketAttribute)


def raise_for_errors(response):
    """Raise an exception if the response returns an error."""
    log.debug("%s response: %s - %s", response.request.method, response.status_code, response.reason)
    try:
        # Let the response decide if it's an error:
        response.raise_for_status()
    except requests.HTTPError as http_err:
        try:
            # Check for Bitbucket Errors:
            j = response.json()
            if "errors" in j:
                for error in j['errors']:
                    log.debug(error.get('message'))
                raise BitbucketServerException(j['errors'], response, http_err) from None
        except ValueError: # catch and ignore JSON parsing errors
            pass
        raise # raise the original HTTPError if no Bitbucket error was found
