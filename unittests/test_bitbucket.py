"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

Test Bitbucket Server

Unit tests for the Bitbucket Wrapper
"""
import os
import sys

parent_dir = os.path.abspath(os.path.join(os.path.split(__file__)[0], '..'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from unittest import mock
import unittest

import json
import requests

from bitbucketserver import bitbucketserver, resources


def fake_response(content=None, code=200, reason="OK"):
    """Creates a genuine Response object with fabricated results."""
    response = requests.Response()
    response.status_code = code
    response.reason = reason
    response.request = mock.Mock(spec=requests.Request)
    response.request.method = 'TEST'
    if content:
        if isinstance(content, dict):
            response._content = bytes(json.dumps(content), 'utf-8')
        else:
            response._content = content
    return response


class TestBitbucketServer(unittest.TestCase):

    def setUp(self):
        self._user = 'testusername'
        self._pass = 'password12345'
        with mock.patch.object(requests, 'Session') as mock_session:
            self.bb = bitbucketserver.BitbucketServer(
                url='http://nope.nope/',
                basic_auth=(self._user, self._pass))
            self.mock_session = self.bb.conn._session

    def tearDown(self):
        self.mock_session = None
        self.bb = None

    def test_mock_configuration(self):
        """Litmus test that the mock config is working."""
        expected_result = {'key': "a_value_i_set"}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(expected_result)
        })

        result = self.bb.conn.get("any address")
        self.assertEqual(result, expected_result)

    def test_fake_response_bad(self):
        """Ensure that we can fake bad responses."""
        response = fake_response(code=404, reason='Not Found')

        with self.assertRaises(requests.HTTPError):
            response.raise_for_status()

    def test_get_user(self):
        test_data = {
            'displayName': 'Test User',
            'slug': 'testuser',
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })

        user = self.bb.user('testuser')

        self.assertTrue(self.mock_session.get.called)
        self.assertIsInstance(user, resources.UserResource)
        self.assertEqual(user._raw, test_data)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('users', kwargs['url'])

    def test_get_user_notfound(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            user = self.bb.user('notavaliduser')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('users', kwargs['url'])

    def test_search_projects(self):
        data_values = [
            {'id': 123456,
             'key': 'PROJA',
             'name': "Project Alpha",
             'public': False,
             'type': "NORMAL"},
            {'id': 1337,
             'key': 'PROJB',
             'name': "Project Beta",
             'public': False,
             'type': "NORMAL"}
        ]
        response = {
            'isLastPage': True,
            'limit': 100,
            'start': 0,
            'values': data_values
        }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = []
        for k in data_values:
            expected_results.append(resources.ProjectResource(k))

        projects = self.bb.projects("somevalue")

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(projects, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projects', kwargs['url'])
        self.assertIn('name', kwargs['params'])

    def test_get_projects(self):
        test_data = {
            'values': [{'key': 'proj1'}, {'key': 'proj2'}, {'key': 'proj3'}],
            'isLastPage': True,
            }
        expected_results = []
        for k in test_data['values']:
            expected_results.append(resources.ProjectResource(k))
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })

        projects = self.bb.projects()

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(projects, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projects', kwargs['url'])

    def test_get_project(self):
        test_data = {
            'id': 123,
            'key': 'TEST',
            'name': 'Test Project',
            'public': False,
            'type': 'NORMAL',
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=test_data),
        })

        project = self.bb.project('test')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(project._raw, test_data)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projects/', kwargs['url'])

    def test_get_project_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            project = self.bb.project('notavalidproject')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projects/', kwargs['url'])

    def test_create_project(self):
        data = {
            'id':123,
            'key': 'TEST',
            'name': 'Test Project',
            'public': False,
            'type': 'NORMAL',
            }
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=data),
        })
        expected_result = resources.ProjectResource(data)

        project = self.bb.create_project('newkey', 'New Project')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(project, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertEqual(kwargs['json'], {'key': 'newkey', 'name': 'New Project'})
        self.assertIn('projects', kwargs['url'])
        self.assertEqual(project.key, data['key'])

    def test_create_project_description(self):
        data = {
            'id': 123,
            'key': 'TEST',
            'name': 'Test Project',
            'public': False,
            'type': 'NORMAL',
            }
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=data),
        })
        expected_result = resources.ProjectResource(data)

        project = self.bb.create_project('newkey', 'New Project', 'Some Description')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(project, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertEqual(kwargs['json'], {'key': 'newkey', 'name': 'New Project', 'description': 'Some Description'})
        self.assertIn('projects', kwargs['url'])

    def test_search_repos_reponame(self):
        data = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=data),
        })
        expected_results = [resources.RepositoryResource(r) for r in data['values']]

        repos = self.bb.search_repos("searchstr")

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repos, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('repos', kwargs['url'])
        self.assertIn('name', kwargs['params'])
        self.assertEqual(kwargs['params']['name'], 'searchstr')

    def test_search_repos_projname(self):
        data = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=data),
        })
        expected_results = [resources.RepositoryResource(r) for r in data['values']]

        repos = self.bb.search_repos(project_name="searchproj")

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repos, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('repos', kwargs['url'])
        self.assertIn('projectname', kwargs['params'])
        self.assertEqual(kwargs['params']['projectname'], 'searchproj')

    def test_get_repos(self):
        data = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=data),
        })
        expected_results = [resources.RepositoryResource(r) for r in data['values']]

        repos = self.bb.repos('projectname')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repos, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])

    def test_get_repo(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.repo('project', 'repo')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])

    def test_get_repo_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            user = self.bb.repo('test_project', 'not_a_repo')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('test_project', kwargs['url'])
        self.assertIn('not_a_repo', kwargs['url'])

    def test_create_new_repo(self):
        """Test creating a repo with the wrapper's defaults."""
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.create_repo('target_proj', 'new_repo')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertEqual(kwargs['json'], {'name': 'new_repo',
                                          'scmId': 'git',
                                          'description': None,
                                          'forkable': True,
                                          'public': False})
        self.assertIn('target_proj', kwargs['url'])
        self.assertTrue(kwargs['url'].endswith('repos'))
        self.assertIn('target_proj', kwargs['url'])

    def test_delete_repo_pass(self):
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(code=202, reason='Accepted'),
        })

        result = self.bb.delete_repo("target_proj", 'condemned_repo')

        self.assertTrue(result)
        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn('target_proj', kwargs['url'])
        self.assertIn('condemned_repo', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])

    def test_delete_repo_not_found(self):
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            result = self.bb.delete_repo('target_proj', 'condemned_repo_404')

        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn('target_proj', kwargs['url'])
        self.assertIn('condemned_repo_404', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])

    def test_delete_repo_delete_fail(self):
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(code=204, reason="No content"),
        })

        with self.assertRaises(Exception):
            result = self.bb.delete_repo('target_proj', 'condemned_repo_404')

        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn('target_proj', kwargs['url'])
        self.assertIn('condemned_repo_404', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])

    def test_update_repo_rename(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', new_name='incognito')

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('name', kwargs['json'])
        self.assertEqual(kwargs['json']['name'], 'incognito')

    def test_update_repo_forkable_true(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', forkable=True)

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('forkable', kwargs['json'])
        self.assertIs(kwargs['json']['forkable'], True)

    def test_update_repo_forkable_false(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', forkable=False)

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('forkable', kwargs['json'])
        self.assertIs(kwargs['json']['forkable'], False)

    def test_update_repo_forkable_notspecified(self):
        """Ensure that not specifying forkable doesn't include it."""
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', new_name='incognito')

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertNotIn('forkable', kwargs['json'])

    def test_update_repo_public_true(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', public=True)

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('public', kwargs['json'])
        self.assertIs(kwargs['json']['public'], True)

    def test_update_repo_public_false(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', public=False)

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('public', kwargs['json'])
        self.assertIs(kwargs['json']['public'], False)

    def test_update_repo_public_notspecified(self):
        """Ensure that not specifying public doesn't include it."""
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.update_repo('project', 'repo', new_name='incognito')

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertNotIn('public', kwargs['json'])

    def test_update_repo_no_changes(self):
        with self.assertRaisesRegex(Exception, "no modification specified"):
            self.bb.update_repo('project', 'repo')

    def test_move_repo(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.move_repo('project', 'repo', new_project='overthere')

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('project', kwargs['json'])
        self.assertEqual(kwargs['json']['project'], {'key': 'overthere'})

    def test_move_repo_rename(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.move_repo('project', 'repo', new_project='overthere', new_name='incognito')

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projects/', kwargs['url'])
        self.assertIn('repos', kwargs['url'])
        self.assertIn('project', kwargs['json'])
        self.assertEqual(kwargs['json']['project'], {'key': 'overthere'})
        self.assertIn('name', kwargs['json'])
        self.assertEqual(kwargs['json']['name'], 'incognito')

    def test_fork_repo(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.fork_repo('src_proj', 'src_repo', 'spork')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertEqual(kwargs['json'], {'name': 'spork'})
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])
        self.assertIn('projects', kwargs['url'])

    def test_fork_repo_given_destination(self):
        data = {
            'slug': 'reposlug',
            'project': 'projectname',
            }
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=data),
        })
        expected_result = resources.RepositoryResource(data)

        repo = self.bb.fork_repo('src_proj', 'src_repo', 'spork', 'dest_proj')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(repo, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertEqual(kwargs['json'], {'name': 'spork',
                                          'project': {'key': 'dest_proj'}})
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])
        self.assertIn('projects', kwargs['url'])

    def test_fork_repo_error(self):
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(code=501, reason="Internal server hemorrhaging"),
        })

        with self.assertRaises(requests.HTTPError):
            repo = self.bb.fork_repo('src_proj', 'src_repo', 'spork', 'dest_proj')

        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])
        self.assertIn('projects', kwargs['url'])
        self.assertEqual('spork', kwargs['json']['name'])
        self.assertEqual('dest_proj', kwargs['json']['project']['key'])

    def test_get_repo_forks(self):
        response = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.RepositoryResource(r) for r in response['values']]

        forks = self.bb.repo_forks('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(forks, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])
        self.assertIn('projects', kwargs['url'])
        self.assertIn('forks', kwargs['url'])

    def test_get_repo_forks_none(self):
        expected_result = {
            'values': [],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        forks = self.bb.repo_forks('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(forks, expected_result['values'])
        self.assertEqual(len(forks), 0)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('forks', kwargs['url'])

    def test_get_repo_forks_projectkey(self):
        response = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.RepositoryResource(r) for r in response['values']]

        forks = self.bb.repo_forks('projectname', 'reponame', project_key='limit')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(forks, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('/repos/', kwargs['url'])
        self.assertIn('projects', kwargs['url'])
        self.assertIn('forks', kwargs['url'])
        self.assertIn('projectKey', kwargs['params'])
        self.assertEqual(kwargs['params']['projectKey'], 'limit')

    def test_get_repo_forks_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            forks = self.bb.repo_forks('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('forks', kwargs['url'])

    def test_get_related_repos(self):
        response = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.RepositoryResource(r) for r in response['values']]

        repos = self.bb.related_repos('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repos, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('related', kwargs['url'])

    def test_get_related_repos_projectkey(self):
        response = {
            'values': [{'slug': 'repo1'}, {'slug': 'repo2'}, {'slug': 'repo3'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.RepositoryResource(r) for r in response['values']]

        repos = self.bb.related_repos('projectname', 'reponame', project_key='limit')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repos, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('related', kwargs['url'])
        self.assertIn('projectKey', kwargs['params'])
        self.assertEqual(kwargs['params']['projectKey'], 'limit')

    def test_get_related_repos_none(self):
        expected_result = {
            'values': [],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        repos = self.bb.related_repos('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(repos, expected_result['values'])
        self.assertEqual(len(repos), 0)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('related', kwargs['url'])

    def test_get_related_repos_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            repos = self.bb.related_repos('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('related', kwargs['url'])

    def test_get_repo_changes_none_specified(self):
        response = {
            'values': [{
                'contentId': 'deadbeefdeadbeefdeadbeef',
                'executable': False,
                'fromContentId': 'deadbeefdeadbeefdeadbeef',
                'link': {},
                'links': {},
                'nodeType': 'FILE',
                'path': {},
                'percentUnchanged': -1,
                'srcExecutable': False,
                'type': 'MODIFY',
            }],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.ChangesResource(c) for c in response['values']]

        commits = self.bb.repo_changes('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('changes', kwargs['url'])
        self.assertIn('until', kwargs['params'])
        self.assertEqual(kwargs['params']['until'], 'HEAD')
        self.assertNotIn('since', kwargs['params'])

    def test_get_repo_changes_since(self):
        response = {
            'values': [{
                'contentId': 'deadbeefdeadbeefdeadbeef',
                'executable': False,
                'fromContentId': 'deadbeefdeadbeefdeadbeef',
                'link': {},
                'links': {},
                'nodeType': 'FILE',
                'path': {},
                'percentUnchanged': -1,
                'srcExecutable': False,
                'type': 'MODIFY',
            }],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.ChangesResource(c) for c in response['values']]

        commits = self.bb.repo_changes('projectname', 'reponame', since='deadbeef')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('changes', kwargs['url'])
        self.assertIn('until', kwargs['params'])
        self.assertEqual(kwargs['params']['until'], 'HEAD')
        self.assertIn('since', kwargs['params'])
        self.assertEqual(kwargs['params']['since'], 'deadbeef')

    def test_get_repo_commits(self):
        response = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.CommitResource(c) for c in response['values']]

        commits = self.bb.repo_commits('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commits_path(self):
        response = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.CommitResource(c) for c in response['values']]

        commits = self.bb.repo_commits('projectname', 'reponame', path='src/tests/')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('path', kwargs['params'])
        self.assertEqual('src/tests/', kwargs['params']['path'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commits_since(self):
        response = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.CommitResource(c) for c in response['values']]

        commits = self.bb.repo_commits('projectname', 'reponame', since='deadbeef')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('since', kwargs['params'])
        self.assertEqual('deadbeef', kwargs['params']['since'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commits_until(self):
        response = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.CommitResource(c) for c in response['values']]

        commits = self.bb.repo_commits('projectname', 'reponame', until='deadbeef')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('until', kwargs['params'])
        self.assertEqual('deadbeef', kwargs['params']['until'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commits_none(self):
        expected_result = {
            'values': [],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        commits = self.bb.repo_commits('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(commits, expected_result['values'])
        self.assertEqual(len(commits), 0)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commits_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            repos = self.bb.repo_commits('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commit(self):
        response = {
            u'author': {
                u'active': True,
                u'displayName': u'Foo Bar',
                u'emailAddress': u'foo_bar@email.com',
                u'id': 2120,
                u'link': {u'rel': u'self', u'url': u'/users/foobar'},
                u'links': {u'self': [{u'href': u'http://notahost/users/foobar'}]},
                u'name': u'foobar',
                u'slug': u'foobar',
                u'type': u'NORMAL'
            },
            u'authorTimestamp': 1459469735000,
            u'displayId': u'3ffeaa6fad7',
            u'id': u'3ffeaa6fad73e23505cfab713b861eb5fe587eb4',
            u'message': u'changed .iteritems to .items for python3 comaptibility',
            u'parents': [
                {
                    u'author': {
                        u'emailAddress': u'foo_bar@email.com',
                        u'name': u'Foo Bar'},
                    u'authorTimestamp': 1459469689000,
                    u'displayId': u'51e1d8d69bb',
                    u'id': u'51e1d8d69bba94db2ebb2dae87c136627d194eca',
                    u'message': u'fixed module imports',
                    u'parents': [{
                        u'displayId': u'f4ecf68ccbc',
                        u'id': u'f4ecf68ccbc24c65e35a516f7ca9e633b7a8f535'}]}]}
        expected_result = resources.CommitResource(response)
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })

        result = self.bb.repo_commit('projectname', 'reponame', 'deadbeef')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(result, expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('commits', kwargs['url'])
        self.assertIn('deadbeef', kwargs['url'])

    def test_get_repo_commit_path(self):
        response = {
            u'author': {
                u'active': True,
                u'displayName': u'Foo Bar',
                u'emailAddress': u'foo_bar@email.com',
                u'id': 2120,
                u'link': {u'rel': u'self', u'url': u'/users/foobar'},
                u'links': {u'self': [{u'href': u'http://notahost/users/foobar'}]},
                u'name': u'foobar',
                u'slug': u'foobar',
                u'type': u'NORMAL'
            },
            u'authorTimestamp': 1459469735000,
            u'displayId': u'3ffeaa6fad7',
            u'id': u'3ffeaa6fad73e23505cfab713b861eb5fe587eb4',
            u'message': u'changed .iteritems to .items for python3 comaptibility',
            u'parents': [
                {
                    u'author': {
                        u'emailAddress': u'foo_bar@email.com',
                        u'name': u'Foo Bar'},
                    u'authorTimestamp': 1459469689000,
                    u'displayId': u'51e1d8d69bb',
                    u'id': u'51e1d8d69bba94db2ebb2dae87c136627d194eca',
                    u'message': u'fixed module imports',
                    u'parents': [{
                        u'displayId': u'f4ecf68ccbc',
                        u'id': u'f4ecf68ccbc24c65e35a516f7ca9e633b7a8f535'}]}]}
        expected_result = resources.CommitResource(response)
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })

        result = self.bb.repo_commit('projectname', 'reponame', 'deadbeef', path='root/path')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(result, expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('commits', kwargs['url'])
        self.assertIn('deadbeef', kwargs['url'])
        self.assertIn('path', kwargs['params'])
        self.assertEqual(kwargs['params']['path'], 'root/path')

    def test_get_repo_commit_stats(self):
        expected_result = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            'authorCount': 2,
            'totalCount': 3,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        author, total = self.bb.repo_commit_stats('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(author, 2)
        self.assertEqual(total, 3)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commit_stats_path(self):
        expected_result = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            'authorCount': 2,
            'totalCount': 3,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        author, total = self.bb.repo_commit_stats('projectname', 'reponame', path='src/tests/')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(author, 2)
        self.assertEqual(total, 3)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('path', kwargs['params'])
        self.assertEqual('src/tests/', kwargs['params']['path'])
        self.assertIn('withCounts', kwargs['params'])
        self.assertTrue(kwargs['params']['withCounts'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commit_stats_since(self):
        expected_result = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            'authorCount': 2,
            'totalCount': 3,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        author, total = self.bb.repo_commit_stats('projectname', 'reponame', since='deadbeef')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(author, 2)
        self.assertEqual(total, 3)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('since', kwargs['params'])
        self.assertEqual('deadbeef', kwargs['params']['since'])
        self.assertIn('withCounts', kwargs['params'])
        self.assertTrue(kwargs['params']['withCounts'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commit_stats_until(self):
        expected_result = {
            'values': [{'author': {'displayName': 'unittest'},
                        'authorTimestamp': 123456,
                        'displayId': 'deadbeef',
                        'id': 'deadbeefdeadbeefdeadbeef',
                        'message': 'commit message',
                        'parents': []}],
            'isLastPage': True,
            'authorCount': 2,
            'totalCount': 3,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        author, total = self.bb.repo_commit_stats('projectname', 'reponame', until="deadbeef")

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(author, 2)
        self.assertEqual(total, 3)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('until', kwargs['params'])
        self.assertEqual('deadbeef', kwargs['params']['until'])
        self.assertIn('withCounts', kwargs['params'])
        self.assertTrue(kwargs['params']['withCounts'])
        self.assertIn('commits', kwargs['url'])

    def test_get_repo_commit_stats_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, "Not found"):
            repos = self.bb.repo_commit_stats('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('withCounts', kwargs['params'])
        self.assertTrue(kwargs['params']['withCounts'])
        self.assertIn('commits', kwargs['url'])

    def test_get_commit_branches(self):
        values = [{'displayId': 'master',
                           'id': 'refs/heads/master',
                           'latestChangeset': 'deadbeefdeadbeef',
                           'latestCommit': 'deadbeefdeadbeef'}]
        response = {
            'isLastPage': True,
            'values': values
        }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_result = [resources.BranchResource(b) for b in values]

        result = self.bb.commit_branches('src_proj', 'src_repo', 'deadbeefhash')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertIn('branches', kwargs['url'])
        self.assertIn('deadbeefhash', kwargs['url'])
        self.assertEqual(result, expected_result)

    def test_branch_repo(self):
        response = {'displayId': 'master',
                           'id': 'refs/heads/master',
                           'latestChangeset': 'deadbeefdeadbeef',
                           'latestCommit': 'deadbeefdeadbeef'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=response),
        })
        expected_result = resources.BranchResource(response)

        branch = self.bb.create_branch('src_proj', 'src_repo', 'new-brunch', 'deadbeefhash')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(branch, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('name', kwargs['json'])
        self.assertEqual(kwargs['json']['name'], 'new-brunch')
        self.assertIn('startPoint', kwargs['json'])
        self.assertEqual(kwargs['json']['startPoint'], 'deadbeefhash')
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertIn('branches', kwargs['url'])

    def test_branch_repo_message(self):
        response = {'displayId': 'master',
                           'id': 'refs/heads/master',
                           'latestChangeset': 'deadbeefdeadbeef',
                           'latestCommit': 'deadbeefdeadbeef'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=response),
        })
        expected_result = resources.BranchResource(response)

        branch = self.bb.create_branch('src_proj', 'src_repo', 'new-brunch', 'deadbeefhash',
                                     message='branched for second breakfast')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(branch, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('name', kwargs['json'])
        self.assertEqual(kwargs['json']['name'], 'new-brunch')
        self.assertIn('startPoint', kwargs['json'])
        self.assertEqual(kwargs['json']['startPoint'], 'deadbeefhash')
        self.assertIn('message', kwargs['json'])
        self.assertEqual(kwargs['json']['message'], 'branched for second breakfast')
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertIn('branches', kwargs['url'])

    def test_branch_repo_not_found(self):
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, 'Not found'):
            branch = self.bb.create_branch('src_proj', 'src_repo', 'new-brunch', 'deadbeefhash')

        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertEqual('new-brunch', kwargs['json']['name'])
        self.assertIn('branches', kwargs['url'])

    def test_branch_repo_error(self):
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(code=501, reason="Internal server hemorrhaging"),
        })

        with self.assertRaises(requests.HTTPError):
            branch = self.bb.create_branch('src_proj', 'src_repo', 'new-brunch', 'deadbeefhash')

        self.assertTrue(self.mock_session.post.called)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('src_proj', kwargs['url'])
        self.assertIn('src_repo', kwargs['url'])
        self.assertEqual('new-brunch', kwargs['json']['name'])
        self.assertIn('branches', kwargs['url'])

    def test_get_repo_branches(self):
        response = {
            'values': [{'displayId': 'master',
                        'id': 'refs/heads/master',
                        'latestChangeset': 'deadbeefdeadbeef',
                        'latestCommit': 'deadbeefdeadbeef'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.BranchResource(b) for b in response['values']]

        branches = self.bb.repo_branches('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(branches, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('branches', kwargs['url'])

    def test_get_repo_branches_base(self):
        response = {
            'values': [{'displayId': 'master',
                        'id': 'refs/heads/master',
                        'latestChangeset': 'deadbeefdeadbeef',
                        'latestCommit': 'deadbeefdeadbeef'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.BranchResource(b) for b in response['values']]

        branches = self.bb.repo_branches('projectname', 'reponame', base='branchname')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(branches, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('base', kwargs['params'])
        self.assertEqual(kwargs['params']['base'], 'branchname')
        self.assertIn('branches', kwargs['url'])

    def test_get_repo_branches_details(self):
        response = {
            'values': [{'displayId': 'master',
                        'id': 'refs/heads/master',
                        'latestChangeset': 'deadbeefdeadbeef',
                        'latestCommit': 'deadbeefdeadbeef'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.BranchResource(b) for b in response['values']]

        branches = self.bb.repo_branches('projectname', 'reponame', details=True)

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(branches, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('details', kwargs['params'])
        self.assertTrue(kwargs['params']['details'])
        self.assertIn('branches', kwargs['url'])

    def test_get_repo_branches_alphabetical(self):
        response = {
            'values': [{'displayId': 'master',
                        'id': 'refs/heads/master',
                        'latestChangeset': 'deadbeefdeadbeef',
                        'latestCommit': 'deadbeefdeadbeef'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.BranchResource(b) for b in response['values']]

        branches = self.bb.repo_branches('projectname', 'reponame', alphabetical=True)

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(branches, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('orderBy', kwargs['params'])
        self.assertEqual(kwargs['params']['orderBy'], 'ALPHABETICAL')
        self.assertIn('branches', kwargs['url'])

    def test_get_repo_branches_filterText(self):
        response = {
            'values': [{'displayId': 'master',
                        'id': 'refs/heads/master',
                        'latestChangeset': 'deadbeefdeadbeef',
                        'latestCommit': 'deadbeefdeadbeef'}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.BranchResource(b) for b in response['values']]

        branches = self.bb.repo_branches('projectname', 'reponame', filterText='foobar')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(branches, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('filterText', kwargs['params'])
        self.assertEqual(kwargs['params']['filterText'], 'foobar')
        self.assertIn('branches', kwargs['url'])

    def test_get_default_branch(self):
        response = {u'displayId': u'master',
            u'id': u'refs/heads/master',
            u'isDefault': True,
            u'latestChangeset': u'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
            u'latestCommit': u'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_result = resources.BranchResource(response)

        default_branch = self.bb.repo_default_branch('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(default_branch, expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('branches/default', kwargs['url'])

    def test_get_default_branch_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason='Not found',
                                              content={'errors':[{'message': 'default branch DNE'}]}),
        })

        with self.assertRaisesRegex(bitbucketserver.BitbucketServerException, 'default branch'):
            default_branch = self.bb.repo_default_branch('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('branches/default', kwargs['url'])

    def test_set_default_branch(self):
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(code=204, reason='No content')
        })

        self.bb.set_repo_default_branch('projectname', 'reponame', 'second-brunch')

        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('id', kwargs['json'])
        self.assertEqual(kwargs['json']['id'], 'second-brunch')
        self.assertIn('branches/default', kwargs['url'])

    def test_set_default_branch_not_found(self):
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(code=404, reason='Not found')
        })

        with self.assertRaisesRegex(requests.HTTPError, 'Not found'):
            self.bb.set_repo_default_branch('projectname', 'reponame', 'second-brunch')

        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('id', kwargs['json'])
        self.assertEqual(kwargs['json']['id'], 'second-brunch')
        self.assertIn('branches/default', kwargs['url'])

    def test_set_default_branch_unauthorized(self):
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(code=401, reason='Unauthorized')
        })

        with self.assertRaisesRegex(requests.HTTPError, 'Unauthorized'):
            self.bb.set_repo_default_branch('projectname', 'reponame', 'second-brunch')

        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('id', kwargs['json'])
        self.assertEqual(kwargs['json']['id'], 'second-brunch')
        self.assertIn('branches/default', kwargs['url'])

    def test_get_repo_tags(self):
        values = [
            {
                u'displayId': u'v0.0.1',
                u'hash': u'c30faab384f6317aa8f7e991ef51c3f387300d5b',
                u'id': u'refs/tags/v0.0.1',
                u'latestChangeset': u'872a3ffecfedafc43b37d3c482e89c23a22357b0',
                u'latestCommit': u'872a3ffecfedafc43b37d3c482e89c23a22357b0'}
        ]
        response = {
            'isLastPage': True,
            'values': values,
        }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response)
        })
        expected_results = [resources.TagResource(t, project='projectname', slug='reponame') for t in values]

        result = self.bb.repo_tags('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(result, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('tags', kwargs['url'])

    def test_get_repo_tags_filtertext(self):
        values = [
            {
                u'displayId': u'v0.0.1',
                u'hash': u'c30faab384f6317aa8f7e991ef51c3f387300d5b',
                u'id': u'refs/tags/v0.0.1',
                u'latestChangeset': u'872a3ffecfedafc43b37d3c482e89c23a22357b0',
                u'latestCommit': u'872a3ffecfedafc43b37d3c482e89c23a22357b0'}
        ]
        response = {
            'isLastPage': True,
            'values': values,
        }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response)
        })
        expected_results = [resources.TagResource(t, project='projectname', slug='reponame') for t in values]

        result = self.bb.repo_tags('projectname', 'reponame', filter_text='filter')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(result, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('tags', kwargs['url'])
        self.assertIn('filterText', kwargs['params'])
        self.assertEqual(kwargs['params']['filterText'], 'filter')

    def test_add_repo_tag(self):
        response = {
            u'displayId': u'v0.0.1',
            u'hash': u'c30faab384f6317aa8f7e991ef51c3f387300d5b',
            u'id': u'refs/tags/v0.0.1',
            u'latestChangeset': u'872a3ffecfedafc43b37d3c482e89c23a22357b0',
            u'latestCommit': u'872a3ffecfedafc43b37d3c482e89c23a22357b0'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=response)
        })
        expected_result = resources.TagResource(response)
        msg = 'ground control to major tom'

        result = self.bb.add_repo_tag('projectname', 'reponame', 'tagname', 'starthash',
                                      message=msg)

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(result, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('tags', kwargs['url'])
        self.assertIn('name', kwargs['json'])
        self.assertEqual(kwargs['json']['name'], 'tagname')
        self.assertIn('message', kwargs['json'])
        self.assertEqual(kwargs['json']['message'], msg)
        self.assertNotEqual(kwargs['json']['type'], 'LIGHTWEIGHT')

    def test_add_repo_tag_lightweight(self):
        response = {
            u'displayId': u'v0.0.1',
            u'hash': u'c30faab384f6317aa8f7e991ef51c3f387300d5b',
            u'id': u'refs/tags/v0.0.1',
            u'latestChangeset': u'872a3ffecfedafc43b37d3c482e89c23a22357b0',
            u'latestCommit': u'872a3ffecfedafc43b37d3c482e89c23a22357b0'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=response)
        })
        expected_result = resources.TagResource(response)
        msg = 'ground control to major tom'

        result = self.bb.add_repo_tag('projectname', 'reponame', 'tagname', 'starthash',
                                      message=msg, lightweight=True)

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(result, expected_result)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('tags', kwargs['url'])
        self.assertIn('name', kwargs['json'])
        self.assertEqual(kwargs['json']['name'], 'tagname')
        self.assertIn('message', kwargs['json'])
        self.assertEqual(kwargs['json']['message'], msg)
        self.assertEqual(kwargs['json']['type'], 'LIGHTWEIGHT')

    def test_delete_repo_tag(self):
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(code=204)
        })

        self.bb.delete_repo_tag('projectname', 'repo_slug', 'tagname')

        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('repo_slug', kwargs['url'])
        self.assertIn('tags', kwargs['url'])
        self.assertIn('tagname', kwargs['url'])

    def test_get_repo_hooks(self):
        response = {
            'values': [{'configured': False,
                        'details':{'configFormKey': 'some.reverse.url.tld',
                                   'description': 'some hook',
                                   'key': 'KW1',
                                   'name': 'Hook Name',
                                   'type': 'PUSH_HOOK',
                                   'version': '0.0.1-b3'},
                        'enabled': False},
                       {'configured': False,
                        'details':{'configFormKey': 'some.reverse.url.tld',
                                   'description': 'some other hook',
                                   'key': 'KW1',
                                   'name': 'Hook Name #2',
                                   'type': 'PUSH_HOOK',
                                   'version': '1.1.0'},
                        'enabled': False}],
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.HookResource(h) for h in response['values']]

        hooks = self.bb.repo_hooks('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(hooks, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])

    def test_get_repo_hooks_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason='Not found'),
        })

        with self.assertRaisesRegex(requests.HTTPError, 'Not found'):
            hooks = self.bb.repo_hooks('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])

    def test_enable_hook(self):
        response = {'configured': True,
                           'details':{'configFormKey': 'some.reverse.url.tld',
                                      'description': 'some hook',
                                      'key': 'KW1',
                                      'name': 'Hook Name',
                                      'type': 'PUSH_HOOK',
                                      'version': '0.0.1-b3'},
                           'enabled': True}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=response),
        })
        expected_result = resources.HookResource(response)

        hook_info = self.bb.enable_hook('projectname', 'reponame', 'hook-key')

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(hook_info, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('enabled', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('enabled', kwargs['url'])

    def test_enable_hook_settings(self):
        response = {'configured': True,
                           'details':{'configFormKey': 'some.reverse.url.tld',
                                      'description': 'some hook',
                                      'key': 'KW1',
                                      'name': 'Hook Name',
                                      'type': 'PUSH_HOOK',
                                      'version': '0.0.1-b3'},
                           'enabled': True}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=response),
        })
        hook_settings = {
            'optionA': True,
            'optionB': 'some/repo/setting'
        }
        expected_result = resources.HookResource(response)

        hook_info = self.bb.enable_hook('projectname', 'reponame', 'hook-key', settings=hook_settings)

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(hook_info, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('json', kwargs)
        self.assertEqual(kwargs['json'], hook_settings)
        self.assertIn('enabled', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('enabled', kwargs['url'])

    def test_enable_hook_error(self):
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(code=400, reason="Internal server hemorrhaging"),
        })

        with self.assertRaises(requests.HTTPError):
            hook_info = self.bb.enable_hook('projectname', 'reponame', 'hook-key')

        self.assertTrue(self.mock_session.put.called)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('enabled', kwargs['url'])

    def test_disable_hook(self):
        response = {'configured': False,
                           'details':{'configFormKey': 'some.reverse.url.tld',
                                      'description': 'some hook',
                                      'key': 'KW1',
                                      'name': 'Hook Name',
                                      'type': 'PUSH_HOOK',
                                      'version': '0.0.1-b3'},
                           'enabled': False}
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(content=response),
        })
        expected_result = resources.HookResource(response)

        hook_info = self.bb.disable_hook('projectname', 'reponame', 'hook-key')

        self.assertTrue(self.mock_session.delete.called)
        self.assertEqual(hook_info, expected_result)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('enabled', kwargs['url'])

    def test_disable_hook_error(self):
        self.mock_session.configure_mock(**{
            'delete.return_value': fake_response(code=400, reason="Internal server hemorrhaging"),
        })

        with self.assertRaises(requests.HTTPError):
            hook_info = self.bb.disable_hook('projectname', 'reponame', 'hook-key')

        self.assertTrue(self.mock_session.delete.called)
        args, kwargs = self.mock_session.delete.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertIn('enabled', kwargs['url'])

    def test_get_hook_settings(self):
        response = {'configured': True,
                           'details':{'configFormKey': 'some.reverse.url.tld',
                                      'description': 'some hook',
                                      'key': 'KW1',
                                      'name': 'Hook Name',
                                      'type': 'PUSH_HOOK',
                                      'version': '0.0.1-b3'},
                           'enabled': True}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        hook_settings = {
            'optionA': True,
            'optionB': 'some/repo/setting'
        }
        expected_result = resources.HookResource(response)

        hook_info = self.bb.hook_settings('projectname', 'reponame', 'hook-key')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(hook_info, expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertTrue(kwargs['url'].endswith('settings'))

    def test_get_hook_settings_error(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=400, reason="Internal server hemorrhaging"),
        })

        with self.assertRaises(requests.HTTPError):
            hook_info = self.bb.hook_settings('projectname', 'reponame', 'hook-key')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertTrue(kwargs['url'].endswith('settings'))

    def test_update_hook_settings(self):
        response = {'configured': True,
                           'details':{'configFormKey': 'some.reverse.url.tld',
                                      'description': 'some hook',
                                      'key': 'KW1',
                                      'name': 'Hook Name',
                                      'type': 'PUSH_HOOK',
                                      'version': '0.0.1-b3'},
                           'enabled': True}
        self.mock_session.configure_mock(**{
            'put.return_value': fake_response(content=response),
        })
        hook_settings = {
            'optionA': True,
            'optionB': 'some/repo/setting'
        }
        expected_result = resources.HookResource(response)

        hook_info = self.bb.update_hook_settings('projectname', 'reponame', 'hook-key', settings=hook_settings)

        self.assertTrue(self.mock_session.put.called)
        self.assertEqual(hook_info, expected_result)
        args, kwargs = self.mock_session.put.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('settings/hooks', kwargs['url'])
        self.assertTrue(kwargs['url'].endswith('settings'))
        self.assertIn('json', kwargs)
        self.assertEqual(kwargs['json'], hook_settings)

    def test_get_branch_model(self):
        response = {
            u'development': {
                u'displayId': u'master',
                u'id': u'refs/heads/master',
                u'isDefault': True,
                u'latestChangeset': u'17167c679aa1c34a6f3011731dea639a46a36ecf',
                u'latestCommit': u'17167c679aa1c34a6f3011731dea639a46a36ecf'},
            u'types': [
                {u'displayName': u'Bugfix',
                 u'id': u'BUGFIX',
                 u'prefix': u'bugfix/'},
                {u'displayName': u'Feature', u'id': u'FEATURE', u'prefix': u'feature/'},
                {u'displayName': u'Hotfix', u'id': u'HOTFIX', u'prefix': u'hotfix/'},
                {u'displayName': u'Release', u'id': u'RELEASE', u'prefix': u'release/'}]}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_result = json.dumps(response, sort_keys=True)

        branch_info = self.bb.repo_branch_model('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(json.dumps(branch_info, sort_keys=True), expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('branchmodel', kwargs['url'])

    def test_get_branch_model_not_found(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=404, reason="Not found"),
        })

        with self.assertRaisesRegex(requests.HTTPError, 'Not found'):
            hook_info = self.bb.repo_branch_model('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('branchmodel', kwargs['url'])

    def test_get_branch_model_error(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=400, reason="Internal server hemorrhaging"),
        })

        with self.assertRaises(requests.HTTPError):
            hook_info = self.bb.repo_branch_model('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('branchmodel', kwargs['url'])

    def test_get_branch_permissions(self):
        data = [{u'id': 1428,
              u'matcher': {u'active': True,
               u'displayId': u'heads/**/develop*',
               u'id': u'heads/**/develop*',
               u'type': {u'id': u'PATTERN', u'name': u'Pattern'}},
              u'type': u'fast-forward-only'},
             {u'id': 1427,
              u'matcher': {u'active': True,
               u'displayId': u'heads/**/develop*',
               u'id': u'heads/**/develop*',
               u'type': {u'id': u'PATTERN', u'name': u'Pattern'}},
              u'type': u'no-deletes'}]
        response = {
            'values': data,
            'isLastPage': True,
            }
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=response),
        })
        expected_results = [resources.SettingsResource(bp) for bp in data]

        branch_perms = self.bb.repo_branch_permissions('projectname', 'reponame')

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(branch_perms, expected_results)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('restrictions', kwargs['url'])

    def test_set_branch_permissions_pattern_empty(self):
        post_returns = {u'id': 1428,
              u'matcher': {u'active': True,
               u'displayId': u'heads/**/develop*',
               u'id': u'heads/**/develop*',
               u'type': {u'id': u'PATTERN', u'name': u'Pattern'}},
              u'type': u'fast-forward-only'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=post_returns),
        })

        self.bb.set_repo_branch_permissions_pattern('projectname', 'reponame', 'pattern**')

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(self.mock_session.post.call_count, 4)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('restrictions', kwargs['url'])

    def test_set_branch_permissions_pattern_names(self):
        post_returns = {u'id': 1428,
              u'matcher': {u'active': True,
               u'displayId': u'heads/**/develop*',
               u'id': u'heads/**/develop*',
               u'type': {u'id': u'PATTERN', u'name': u'Pattern'}},
              u'type': u'fast-forward-only'}
        self.mock_session.configure_mock(**{
            'post.return_value': fake_response(content=post_returns),
        })
        names = (['user1', 'user2'], ['group1', 'group2'])

        self.bb.set_repo_branch_permissions_pattern(
            'projectname', 'reponame', 'pattern**',
            write_access=names,
            pull_request=names,
            branch_delete=names,
            rewrite_history=names)

        self.assertTrue(self.mock_session.post.called)
        self.assertEqual(self.mock_session.post.call_count, 4)
        args, kwargs = self.mock_session.post.call_args
        self.assertIn('projectname', kwargs['url'])
        self.assertIn('reponame', kwargs['url'])
        self.assertIn('restrictions', kwargs['url'])



    def test_connection_good(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content={'username': 'doesntmatter'}),
        })

        status = self.bb.test_connection()

        self.assertTrue(self.mock_session.get.called)
        self.assertTrue(status)

    def test_connection_bad(self):
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(code=400, reason="Internal server hemorrhaging"),
        })

        status = self.bb.test_connection()

        self.assertTrue(self.mock_session.get.called)
        self.assertFalse(status)

    def test_connection_very_bad(self):
        self.mock_session.configure_mock(**{
            'get.side_effect': RuntimeError('connection go boom')
        })

        status = self.bb.test_connection()

        self.assertTrue(self.mock_session.get.called)
        self.assertFalse(status)

    def test_server_info(self):
        expected_result = {
            u'buildDate': u'1437391865158',
            u'buildNumber': u'3011001',
            u'displayName': u'Stash',
            u'version': u'3.11.1'}
        self.mock_session.configure_mock(**{
            'get.return_value': fake_response(content=expected_result),
        })

        server_info = self.bb.server_info()

        self.assertTrue(self.mock_session.get.called)
        self.assertEqual(server_info, expected_result)
        args, kwargs = self.mock_session.get.call_args
        self.assertIn('application-properties', kwargs['url'])

    def test_coverage(self):
        methods = [
            ('server_info', []),
            ('users', []),
            ('users', [{'filter': "name"}]),
            ('groups', []),
            ('groups', ['filter']),
            ('group_membership', ['groupname']),
            ('user', ['username']),
            ('current_user', []),
            #('update_user_avatar', ['username', 'filename']),
            ('projects', []),
            ('projects', ['name', 'permission']),
            ('project', ['TEST']),
            ('project_group_permissions', ['TEST']),
            ('project_group_permissions', ['TEST', 'filter']),
            ('project_group_no_permissions', ['TEST', 'filter']),
            ('set_project_group_permission', ['TEST', 'group', 'PROJECT_READ']),
            ('delete_project_group_permission', ['TEST', 'group']),
            ('project_user_permissions', ['TEST']),
            ('project_user_permissions', ['TEST', 'group']),
            ('project_user_no_permissions', ['TEST']),
            ('project_user_no_permissions', ['TEST', 'group']),
            ('project_user_permissions', ['TEST']),
            ('project_user_permissions', ['TEST', 'filter']),
            ('project_user_no_permissions', ['TEST', 'filter']),
            ('set_project_user_permission', ['TEST', 'user', 'PROJECT_READ']),
            ('delete_project_user_permission', ['TEST', 'user']),
            ('project_default_permission', ['TEST', 'PROJECT_READ']),
            ('set_project_default_permission', ['TEST', 'PROJECT_READ', True]),
            ('project_audit', ['TEST']),
            ('search_repos', ['TEST']),
            ('repos', ['TEST']),
            ('repo', ['TEST', 'slug']),
            ('repo_by_id', [1234]),
            ('create_repo', ['TEST', 'Name']),
            ('create_repo', ['TEST', 'Name', 'description']),
            ('update_repo', ['TEST', 'slug', 'description', 'new name']),
            ('update_repo', ['TEST', 'slug', None, 'new name']),
            ('update_repo', ['TEST', 'slug', None, 'new name', False, False]),
            ('repo_git_lfs_status', ['TEST', 'slug']),
            ('enable_git_lfs_in_repo', ['TEST', 'slug']),
            ('disable_git_lfs_in_repo', ['TEST', 'slug']),
            ('move_repo', ['TEST', 'slug', 'NEWPROJ']),
            ('move_repo', ['TEST', 'slug', 'NEWPROJ', "New Name"]),
            ('fork_repo', ['TEST', 'slug', 'Fork Name', "NEWPROJ"]),
            ('repo_forks', ['TEST', 'slug']),
            ('repo_forks', ['TEST', 'slug', 'PROJ']),
            ('related_repos', ['TEST', 'slug']),
            ('related_repos', ['TEST', 'slug', 'PROJ']),
            ('repo_group_permissions', ['TEST', 'slug']),
            ('repo_group_permissions', ['TEST', 'slug', 'filter']),
            ('repo_group_no_permissions', ['TEST', 'slug', 'filter']),
            ('set_repo_group_permission', ['TEST', 'slug', 'group', 'REPO_READ']),
            ('delete_repo_group_permission', ['TEST', 'slug', 'group']),
            ('repo_user_permissions', ['TEST', 'slug']),
            ('repo_user_permissions', ['TEST', 'slug', 'group']),
            ('repo_user_no_permissions', ['TEST', 'slug']),
            ('repo_user_no_permissions', ['TEST', 'slug', 'group']),
            ('repo_user_permissions', ['TEST', 'slug']),
            ('repo_user_permissions', ['TEST', 'slug', 'filter']),
            ('repo_user_no_permissions', ['TEST', 'slug', 'filter']),
            ('set_repo_user_permission', ['TEST', 'slug', 'user', 'REPO_READ']),
            ('delete_repo_user_permission', ['TEST', 'slug', 'user']),
            ('repo_audit', ['TEST', 'slug']),
            ('repo_changes', ['TEST', 'slug']),
            ('repo_changes', ['TEST', 'slug', 'HEAD', 'since']),
            ('file_diff', ['TEST', 'slug', '/path', 'HEAD']),
            ('file_diff', ['TEST', 'slug', '/path', 'HEAD', 'since']),
            ('file_diff', ['TEST', 'slug', '/path', 'HEAD', 'since', True, 25]),
            ('compare_changes', ['TEST', 'slug']),
            ('compare_changes', ['TEST', 'slug', 'from', 'to', 'fromrepo']),
            ('repo_commits', ['TEST', 'slug', '/path', 'since', 'until']),
            ('repo_commit', ['TEST', 'slug', 'hashhash']),
            ('repo_commit', ['TEST', 'slug', 'hashhash', '/path']),
            ('repo_commit_changes', ['TEST', 'slug', 'hashhash']),
            ('repo_commit_changes', ['TEST', 'slug', 'hashhash', 'since', False]),
            ('commit_pull_requests', ['TEST', 'slug', 'hashhash']),
            ('repo_commit_stats', ['TEST', 'slug']),
            ('repo_commit_stats', ['TEST', 'slug', '/path', 'since', 'until']),
            ('commit_branches', ['TEST', 'slug', 'hashhash']),
            ('file_contents', ['TEST', 'slug', 'filepath']),
            ('file_contents', ['TEST', 'slug', '/filepath']),
            ('file_contents', ['TEST', 'slug', 'filepath', 'HEAD']),
            ('repo_files', ['TEST', 'slug']),
            ('repo_files', ['TEST', 'slug', '/filepath']),
            ('repo_files', ['TEST', 'slug', 'filepath', 'HEAD']),
            ('raw_file', ['TEST', 'slug', '/filepath']),
            ('raw_file', ['TEST', 'slug', 'filepath', 'HEAD']),
            ('delete_branch', ['TEST', 'slug', 'branchname']),
            ('repo_default_branch', ['TEST', 'slug']),
            ('set_repo_default_branch', ['TEST', 'slug', 'branchname']),
            ('repo_tags', ['TEST', 'slug']),
            ('repo_shortcut_links', ['TEST', 'slug']),
            ('create_new_repo_shortcut_link', ['TEST', 'slug', 'url', 'label']),
            ('update_repo_shortcut_link', ['TEST', 'slug', 'id', 'url', 'label']),
            ('delete_repo_shortcut_link', ['TEST', 'slug', 'id']),
            ('pull_request_settings', ['TEST', 'slug']),
            ('set_pull_request_settings', ['TEST', 'slug']),
            ('set_pull_request_settings', ['TEST', 'slug', 'approvers', 'tasks', 'successful']),
            ('repo_branch_permissions', ['TEST', 'slug']),
            ('set_repo_branch_model', ['TEST', 'slug', {}]),
            ('commit_build_status', ['project', 'slug', 'hash', 'unique-key']),
            ('delete_commit_build_status', ['project', 'slug', 'hash', 'unique-key']),
            ('commit_build_statuses', ['hash']),
            ('commit_build_statistics', ['hash']),
            ('commit_build_statistics', ['hash', 'includeunique']),
            ('post_build_status_legacy', ['commithash', 'FAILED', 'keyname', 'url']),
            ('post_build_status_legacy', ['commithash', 'FAILED', 'keyname', 'url', 'Name', 'description']),
            ('issue_commits', ['JRA-123']),
            ('create_pull_request', ['Title', 'from', 'to', 'from', 'from']),
            ('create_pull_request', ['Title', 'from', 'to', 'from', 'from', 'to', 'to', [], 'descrip']),
            ('pull_requests', ['project', 'slug']),
            ('pull_requests', ['project', 'slug', True, 'branch', 'outgoing', True, 'state']),
            ('pull_request', ['project', 'slug', 'id']),
            ('update_pull_request_info', ['project', 'slug', 'id', 'title', 'description']),
            ('add_user_to_pull_request', ['project', 'slug', 'id', 'username']),
            ('pull_request_participants', ['project', 'slug', 'id']),
            ('update_pull_request_participant', ['project', 'slug', 'id', 'username']),
            ('update_pull_request_participant', ['project', 'slug', 'id', 'username', 'role', 'status']),
            ('remove_user_from_pull_request', ['project', 'slug', 'id', 'username']),
            ('approve_pull_request', ['project', 'slug', 'id']),
            ('approve_pull_request', ['project', 'slug', 'id', 'username']),
            ('decline_pull_request', ['project', 'slug', 'id', 'version']),
            ('merge_pull_request', ['project', 'slug', 'id', 'version']),
            ('pull_request_merge_status', ['project', 'slug', 'id']),
            ('reopen_pull_request', ['project', 'slug', 'id', 'version']),
            ('pull_request_activities', ['project', 'slug', 'id']),
            ('pull_request_activities', ['project', 'slug', 'id', 'from', 'type']),
            ('pull_request_changes', ['project', 'slug', 'id']),
            ('pull_request_commits', ['project', 'slug', 'id']),
            ('pull_request_comments', ['project', 'slug', 'id', 'path']),
            ('pull_request_diffs', ['project', 'slug', 'id']),
            ('pull_request_diffs', ['project', 'slug', 'id', 'path']),
            ('pull_request_diffs', ['project', 'slug', 'id', 'path', 'context', 'difftype', 'since', 'until', 'srcpath', 'whitespace', 'comments']),
            ('pull_request_tasks', ['project', 'slug', 'id']),
            ('task', ['id']),
            ('resolve_task', ['id']),
            ('open_task', ['id']),
            ('delete_task', ['id']),
            ('update_task', ['id']),
            ('update_task', ['id', 'text', 'state']),
            ('user_ssh_keys', []),
            ('user_ssh_keys', ['username']),
            ('add_user_ssh_key', ['sshkey']),
            ('add_user_ssh_key', ['sshkey', 'username']),
            ('project_ssh_keys', ['project']),
            ('project_ssh_keys', ['project', 'filter', 'permission']),
            ('repo_ssh_keys', ['project', 'slug']),
            ('repo_ssh_keys', ['project', 'slug', 'filter', 'permission']),
            ('add_repo_ssh_key', ['project', 'slug', 'key', 'permission']),
            ('add_repo_ssh_key', ['project', 'slug', 'key', 'permission']),
            ('user_access_tokens', ['username']),
            ('user_access_token', ['username', 'tokenid']),
            ('create_user_access_token', ['username', 'token_name', 'permission']),
            ('update_user_access_token', ['username', 'tokenid']),
            ('update_user_access_token', ['username', 'tokenid', 'name', 'permission']),
            ('delete_user_access_token', ['username', 'tokenid']),
            ('label', ['label']),
            ('labeled_items', ['label']),
            ('labeled_items', ['label', 'type']),
            ('repo_labels', ['project', 'slug']),
            ('add_repo_label', ['project', 'slug', 'label']),
            ('delete_repo_label', ['project', 'slug', 'label']),
            ('repo_webhooks', ['project', 'slug']),
            ('repo_webhook', ['project', 'slug', 'hook']),
            ('webhook_latest_event', ['project', 'slug', 'hook']),
            ('webhook_statistics', ['project', 'slug', 'hook']),
            ('webhook_statistics_summary', ['project', 'slug', 'hook']),
            ('code_insight_reports', ['project', 'slug', 'commit']),
            ('code_insight_report', ['project', 'slug', 'commit', 'report_key']),
            ('delete_code_insight_report', ['project', 'slug', 'commit', 'report_key']),
            ('create_code_insight_report', ['project', 'slug', 'commit', 'report_key', 'json']),
            ('add_code_insight_report_annotations', ['project', 'slug', 'commit', 'report_key', 'annotations']),
            ('add_code_insight_report_annotations', ['project', 'slug', 'commit', 'report_key', 'annotations', 'external_id']),
            ('code_insight_report_annotations', ['project', 'slug', 'commit', 'report_key']),
            ('delete_code_insight_report_annotations', ['project', 'slug', 'commit', 'report_key']),
            ('delete_code_insight_report_annotations', ['project', 'slug', 'commit', 'report_key', 'external']),
            ('commit_code_insight_annotations', ['project', 'slug', 'commit', 'report_key', 'external', 'path', 'severity', 'type']),
        ]
        for method_name, args in methods:
            with self.subTest(f"{method_name}({args})"):
                self.mock_session.reset_mock()

                method = getattr(self.bb, method_name)
                results = method(*args)

                self.assertTrue(
                    any([
                        self.mock_session.get.called,
                        self.mock_session.put.called,
                        self.mock_session.post.called,
                        self.mock_session.delete.called
                    ])
                )

if __name__ == '__main__':
    unittest.main(verbosity=2)
