"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

Test BitbucketServer Connection

Unit tests for the Stash/Bitbucket connection object
"""
import os
import sys

parent_dir = os.path.abspath(os.path.join(os.path.split(__file__)[0], '..'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import requests
from unittest import mock
import unittest
from .test_bitbucket import fake_response

from bitbucketserver import connection
from bitbucketserver.bitbucketserver import APIVersions


class BitbucketServerConnection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._user = 'testusername'
        cls._pass = 'password12345'
        cls._url  = 'http://invalid/'
        cls._base = APIVersions()

    def setUp(self):
        self.conn = connection.BitbucketConnection(
            url=self._url,
            api_versions=self._base,
            basic_auth=(self._user, self._pass),
            verify=False)
        self.conn._session = mock.Mock(spec=requests.Session)
        self.mock_session = self.conn._session


    def tearDown(self):
        pass
        #self.conn = None

    def test_session_creation(self):
        conn = connection.BitbucketConnection(
            url=self._url,
            api_versions=self._base,
            basic_auth=(self._user, self._pass),
            verify=False)
        self.assertEqual(conn.session.auth, (self._user, self._pass))
        self.assertEqual(conn.verify, conn.session.verify)
        self.assertIsNotNone(conn._session)

    def test_test_good(self):
        test_data = {'user': 'root'}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })

        response = self.conn.test()

        self.assertTrue(response)
        self.assertIs(response, True)
        self.assertTrue(self.mock_session.get.called)

    def test_test_bad(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=500, reason='error'),
        })

        response = self.conn.test()

        self.assertFalse(response)
        self.assertIs(response, False)
        self.assertTrue(self.mock_session.get.called)

    def test_get_good(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'

        response = self.conn.get(test_uri)

        self.assertEqual(response, test_data)
        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_get_bad(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason='did not get good'),
        })
        test_uri = 'some/uri/path'

        with self.assertRaises(requests.HTTPError):
            self.conn.get('some/uri/path')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_get_params(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        test_params = {'at': 'somehash', 'q': 'querytext'}

        response = self.conn.get(test_uri, parameters=test_params)

        self.assertEqual(response, test_data)
        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertEqual(test_params, kwargs['params'])

    def test_get_base(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        test_base = 'diff/base/'

        response = self.conn.get(test_uri, base=test_base)

        self.assertEqual(response, test_data)
        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn(test_base, kwargs['url'])
        self.assertNotIn(self.conn._default_base, kwargs['url'])

    def test_get_paged(self):
        response_contents = [
            {'values': [{'value': 'a'}],
             'isLastPage': False,
             'nextPageStart': 25},
            {'values': [{'value': 'b'}],
             'isLastPage': False,
             'nextPageStart': 50},
            {'values': [{'value': 'c'}, {'value': 'g'}],
             'isLastPage': False,
             'nextPageStart': 75},
            {'values': [{'value': 'd'}],
             'isLastPage': False,
             'nextPageStart': 100},
            {'values': [{'value': 'e'}],
             'isLastPage': False,
             'nextPageStart': 125},
            {'values': [{'value': 'f'}],
             'isLastPage': True},
        ]
        packets = []
        expected_results = []
        for page in response_contents:
            packets.append(fake_response(content=page))
            for item in page['values']:
                expected_results.append(item)
        self.mock_session.configure_mock(**{
            'get.side_effect': packets,
        })

        results = self.conn.get_paged('some/path/uri')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(self.mock_session.get.call_count, len(response_contents))
        self.assertEqual(expected_results, results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('some/path/uri', kwargs['url'])

    def test_get_paged_params(self):
        """Tests that parameters are passed along all requests."""
        response_contents = [
            {'values': [{'value': 'a'}],
             'isLastPage': False,
             'nextPageStart': 25},
            {'values': [{'value': 'b'}],
             'isLastPage': False,
             'nextPageStart': 50},
            {'values': [{'value': 'c'}, {'value': 'g'}],
             'isLastPage': False,
             'nextPageStart': 75},
            {'values': [{'value': 'd'}],
             'isLastPage': False,
             'nextPageStart': 100},
            {'values': [{'value': 'e'}],
             'isLastPage': False,
             'nextPageStart': 125},
            {'values': [{'value': 'f'}],
             'isLastPage': True},
        ]
        packets = []
        expected_results = []
        for page in response_contents:
            packets.append(fake_response(content=page))
            for item in page['values']:
                expected_results.append(item)
        self.mock_session.configure_mock(**{
            'get.side_effect': packets,
        })
        test_params = {'q': 'query'}

        results = self.conn.get_paged('some/path/uri', parameters=test_params)

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(self.mock_session.get.call_count, len(response_contents))
        self.assertEqual(expected_results, results)
        for call in self.mock_session.get.call_args_list:
            args, kwargs = call
            self.assertIn('some/path/uri', kwargs['url'])
            self.assertIn('q', kwargs['params'])
            self.assertEqual(test_params['q'], kwargs['params']['q'])

    def test_get_paged_lines(self):
        """Test get_paged with a different key."""
        response_contents = [
            {'lines': [{'value': 'a'}],
             'isLastPage': False,
             'nextPageStart': 25},
            {'lines': [{'value': 'b'}],
             'isLastPage': False,
             'nextPageStart': 50},
            {'lines': [{'value': 'c'}, {'value': 'g'}],
             'isLastPage': False,
             'nextPageStart': 75},
            {'lines': [{'value': 'd'}],
             'isLastPage': False,
             'nextPageStart': 100},
            {'lines': [{'value': 'e'}],
             'isLastPage': False,
             'nextPageStart': 125},
            {'lines': [{'value': 'f'}],
             'isLastPage': True},
        ]
        packets = []
        expected_results = []
        for page in response_contents:
            packets.append(fake_response(content=page))
            for item in page['lines']:
                expected_results.append(item)
        self.mock_session.configure_mock(**{
            'get.side_effect': packets,
        })

        results = self.conn.get_paged('some/path/uri', key='lines')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(self.mock_session.get.call_count, len(response_contents))
        self.assertEqual(expected_results, results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('some/path/uri', kwargs['url'])

    def test_get_paged_no_next_page(self):
        """Tests that nextPageStart can be calculated."""
        response_contents = [
            {'lines': [{'value': 'a'}],
             'isLastPage': False,
             'size': 25,
             'start': 0},
            {'lines': [{'value': 'b'}],
             'isLastPage': False,
             'size': 25,
             'nextPageStart': 25},
            {'lines': [{'value': 'c'}, {'value': 'g'}],
             'isLastPage': False,
             'size': 25,
             'nextPageStart': 50},
            {'lines': [{'value': 'd'}],
             'isLastPage': False,
             'size': 25,
             'nextPageStart': 75},
            {'lines': [{'value': 'e'}],
             'isLastPage': False,
             'size': 25,
             'nextPageStart': 100},
            {'lines': [{'value': 'f'}],
             'size': 25,
             'isLastPage': True},
        ]
        packets = []
        expected_results = []
        for page in response_contents:
            packets.append(fake_response(content=page))
            for item in page['lines']:
                expected_results.append(item)
        self.mock_session.configure_mock(**{
            'get.side_effect': packets
        })

        results = self.conn.get_paged('some/path/uri', key='lines')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(self.mock_session.get.call_count, len(response_contents))
        self.assertEqual(expected_results, results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('some/path/uri', kwargs['url'])

    def test_post_good(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'

        response = self.conn.post(test_uri)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_post_json(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        data = {'some': 'data'}

        response = self.conn.post(test_uri, json=data)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn('json', kwargs)
        self.assertEqual(data, kwargs['json'])

    def test_post_content(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        content = "some text content"

        response = self.conn.post(test_uri, content=content)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn('data', kwargs)
        self.assertEqual(content, kwargs['data'])

    def test_post_bad(self):
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(code=404, reason='not found'),
        })
        test_uri = 'some/uri/path'

        with self.assertRaises(requests.HTTPError):
            self.conn.post('some/uri/path')

        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_post_params(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        test_params = {'at': 'somehash', 'q': 'querytext'}

        response = self.conn.post(test_uri, parameters=test_params)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertEqual(test_params, kwargs['params'])

    def test_post_base(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        test_base = 'diff/base/'

        response = self.conn.post(test_uri, base=test_base)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn(test_base, kwargs['url'])
        self.assertNotIn(self.conn._default_base, kwargs['url'])

    def test_put_good(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'

        response = self.conn.put(test_uri)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_put_json(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        data = {'some': 'data'}

        response = self.conn.put(test_uri, json=data)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn('json', kwargs)
        self.assertEqual(data, kwargs['json'])

    def test_put_content(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        content = "some text content"

        response = self.conn.put(test_uri, content=content)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn('data', kwargs)
        self.assertEqual(content, kwargs['data'])

    def test_put_bad(self):
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(code=404, reason='not found'),
        })
        test_uri = 'some/uri/path'

        with self.assertRaises(requests.HTTPError):
            self.conn.put('some/uri/path')

        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_put_base(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        test_base = 'rest/differentbase/1.0/'

        response = self.conn.put(test_uri, base=test_base)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn(test_base, kwargs['url'])
        self.assertNotIn(self.conn._default_base, kwargs['url'])

    def test_delete_good(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'

        response = self.conn.delete(test_uri)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_delete_content(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        content = "some text content"

        response = self.conn.delete(test_uri, content=content)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn('data', kwargs)
        self.assertEqual(content, kwargs['data'])

    def test_delete_bad(self):
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(code=404, reason='not found'),
        })
        test_uri = 'some/uri/path'

        with self.assertRaises(requests.HTTPError):
            self.conn.delete('some/uri/path')

        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn(test_uri, kwargs['url'])

    def test_delete_base(self):
        test_data = {'id': '1234', 'key': 'dont care'}
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(content=test_data),
        })
        test_uri = 'some/uri/path'
        test_base = 'diff/base/'

        response = self.conn.delete(test_uri, base=test_base)

        self.assertEqual(response.json(), test_data)
        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn(test_uri, kwargs['url'])
        self.assertIn(test_base, kwargs['url'])
        self.assertNotIn(self.conn._default_base, kwargs['url'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
