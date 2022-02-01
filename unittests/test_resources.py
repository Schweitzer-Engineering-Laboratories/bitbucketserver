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

from bitbucketserver import BitbucketServer
from bitbucketserver import resources
from bitbucketserver import utils

from unittests.test_bitbucket import fake_response

class TestResourcesBase(unittest.TestCase):

    def setUp(self):
        self._user = 'testusername'
        self._pass = 'password12345'
        with mock.patch.object(requests, 'Session') as mock_session:
            self.bb = BitbucketServer(
                url='http://nope.nope/',
                basic_auth=(self._user, self._pass))
            self.mock_session = self.bb.conn._session

    def bb_objectify(self, d):
        return json.loads(json.dumps(d), object_hook=resources.BitbucketAttribute)


class TestJSONEncoder(TestResourcesBase):

    def test_encoder(self):
        d = {
            'slug': "TEST",
            'id': 1003,
            'name': "TEST",
            'project': {'key': "PRJ", "name": "Project", 'id': 1234}
        }
        fake_repo = resources.RepositoryResource(d)
        self.assertIsInstance(fake_repo, resources.BitbucketObject)

        result = json.dumps(fake_repo, cls=utils.BitbucketJsonEncoder,
            sort_keys=True)

        tc = json.dumps(d, sort_keys=True)
        self.assertEqual(tc, result)


class ResourceCoverage(TestResourcesBase):

    def test_coverage_repo_related_functions(self):
        cases = [
            (resources.BaseRefResourceObject, 'files', []),
            (resources.BaseRefResourceObject, 'files', ['/path']),
            (resources.BaseRefResourceObject, 'file_contents', ['/path']),
            (resources.BaseRefResourceObject, 'raw_file', ['/path']),
            (resources.BranchResource, 'create_outgoing_pull_request', ['title', 'toref']),
            (resources.BranchResource, 'create_incoming_pull_request', ['title', 'fromref']),
            (resources.BranchResource, 'commits', []),
            (resources.BranchResource, 'delete', []),
            (resources.BranchResource, 'set_as_default_branch', []),
            (resources.CommitResource, 'branches', []),
            (resources.CommitResource, 'build_statuses', []),
            (resources.CommitResource, 'add_build', ['state', 'key', 'url']),
            (resources.CommitResource, 'build_statistics', []),
            (resources.CommitResource, 'changes', []),
            (resources.CommitResource, 'changes_since', ['since']),
            (resources.CommitResource, 'code_insight_reports', []),
            (resources.CommitResource, 'code_insight_report', ['key']),
            (resources.CommitResource, 'create_code_insight_report', ['key', 'insight_json']),
            (resources.CommitResource, 'code_insight_annotations', []),
            (resources.CommitResource, 'add_tag', ['new_tag', 'msg']),
            (resources.CommitResource, 'tags', []),
            (resources.CommitResource, 'pull_requests', []),
            (resources.HookResource, 'enable', []),
            # (resources.HookResource, 'disable', []),
            (resources.HookResource, 'update', []),
            # (resources.ProjectAuditResource, 'detail_dictionary', []),
            (resources.ProjectResource, 'audit', []),
            (resources.ProjectResource, 'repos', []),
            (resources.ProjectResource, 'repo', ['slug']),
            (resources.ProjectResource, 'create_repo', ['name']),
            (resources.ProjectResource, 'search_repos', []),
            (resources.ProjectResource, 'delete_repo', ['slug']),
            # (resources.ProjectResource, 'delete', []),
            (resources.ProjectResource, 'group_permissions', []),
            (resources.ProjectResource, 'group_no_permissions', []),
            (resources.ProjectResource, 'set_group_permission', ['group', 'PROJECT_READ']),
            (resources.ProjectResource, 'delete_group_permission', ['group']),
            (resources.ProjectResource, 'user_permissions', []),
            (resources.ProjectResource, 'user_no_permissions', []),
            (resources.ProjectResource, 'set_user_permission', ['user', 'PROJECT_READ']),
            (resources.ProjectResource, 'delete_user_permission', ['user']),
            (resources.ProjectResource, 'get_default_permission', ['PROJECT_READ']),
            (resources.ProjectResource, 'set_default_permission', ['PROJECT_READ', True]),
            (resources.PullRequestResource, 'tasks', []),
            (resources.PullRequestResource, 'approve', []),
            (resources.PullRequestResource, 'decline', []),
            (resources.PullRequestResource, 'merge', []),
            (resources.PullRequestResource, 'merge_status', []),
            (resources.PullRequestResource, 'reopen', []),
            (resources.PullRequestResource, 'activities', []),
            (resources.PullRequestResource, 'changes', []),
            (resources.PullRequestResource, 'commits', []),
            (resources.PullRequestResource, 'comments', ['path']),
            (resources.PullRequestResource, 'comments', ['some/file.txt', 'NONE']),
            (resources.PullRequestResource, 'diffs', []),
            (resources.PullRequestResource, 'diffs', ['some/file.txt', 3, 'UNKNOWN', 'deadbeef', 'beefdead', 'original/path.txt', False, True]),
            (resources.RepositoryResource, 'audit', []),
            (resources.RepositoryResource, 'create_outgoing_pull_request', ['title', 'from', 'to']),
            (resources.RepositoryResource, 'create_incoming_pull_request', ['title', 'from', 'to']),
            (resources.RepositoryResource, 'commit', ['hash', 'path']),
            (resources.RepositoryResource, 'commits', []),
            (resources.RepositoryResource, 'compare_changes', []),
            (resources.RepositoryResource, 'forks', []),
            (resources.RepositoryResource, 'fork_repo', ['name', 'project']),
            (resources.RepositoryResource, 'related_repos', []),
            (resources.RepositoryResource, 'create_branch', ['branch', 'ref']),
            (resources.RepositoryResource, 'branches', []),
            (resources.RepositoryResource, 'delete_branch', ['branch']),
            (resources.RepositoryResource, 'default_branch', []),
            (resources.RepositoryResource, 'set_default_branch', ['name']),
            (resources.RepositoryResource, 'files', []),
            (resources.RepositoryResource, 'file_contents', ['filename']),
            (resources.RepositoryResource, 'raw_file', ['path']),
            (resources.RepositoryResource, 'tags', []),
            (resources.RepositoryResource, 'add_tag', ['name', 'ref', 'msg']),
            (resources.RepositoryResource, 'delete_tag', ['tagname']),
            (resources.RepositoryResource, 'hooks', []),
            (resources.RepositoryResource, 'update', ['name']),
            (resources.RepositoryResource, 'update', ['name', 'description', True, True]),
            (resources.RepositoryResource, 'move', ['project']),
            (resources.RepositoryResource, 'delete', []),
            (resources.RepositoryResource, 'pull_request', ['id']),
            (resources.RepositoryResource, 'pull_requests', []),
            (resources.RepositoryResource, 'pull_request_settings', []),
            (resources.RepositoryResource, 'set_pull_request_settings', []),
            (resources.RepositoryResource, 'add_access_key', ['key', 'permissions']),
            (resources.RepositoryResource, 'group_permissions', []),
            (resources.RepositoryResource, 'group_no_permissions', []),
            (resources.RepositoryResource, 'set_group_permission', ['group', 'PROJECT_READ']),
            (resources.RepositoryResource, 'delete_group_permission', ['group']),
            (resources.RepositoryResource, 'user_permissions', []),
            (resources.RepositoryResource, 'user_no_permissions', []),
            (resources.RepositoryResource, 'set_user_permission', ['user', 'PROJECT_READ']),
            (resources.RepositoryResource, 'delete_user_permission', ['user']),
            (resources.RepositoryResource, 'webhooks', []),
            (resources.RepositoryResource, 'webhook', ['id']),
            (resources.RepositoryResource, 'enable_git_lfs', []),
            (resources.RepositoryResource, 'disable_git_lfs', []),
            (resources.TagResource, 'delete', []),
            (resources.TaskResource, 'resolve', []),
            (resources.TaskResource, 'delete', []),
            (resources.TaskResource, 'open', []),
            (resources.TaskResource, 'update', ['new text']),

            (resources.UserResource, 'repos', []),
            (resources.UserResource, 'ssh_keys', []),
            (resources.UserResource, 'add_ssh_key', ['sshkey']),
            (resources.UserResource, 'access_tokens', []),
            (resources.UserAccessToken, 'update', ['token name']),
            (resources.UserAccessToken, 'delete', []),

            (resources.CodeInsightReport, 'add_annotations', [{'key': "value"}]),
            (resources.CodeInsightReport, 'delete_annotations', []),
            (resources.CodeInsightReport, 'delete', []),
            (resources.WebhookResource, 'latest_event', []),
            (resources.WebhookResource, 'statistics', []),
            (resources.WebhookResource, 'statistics_summary', []),


        ]
        for testclass, method_name, args in cases:
            with self.subTest(f"{testclass}.{method_name}({args})"):
                self.mock_session.reset_mock()
                self.mock_session.delete.return_value = fake_response(code=202)

                resource_dict = {'id': 123, 'displayId': 'display', 'parents': [],
                    'details': {'key': 'TEST'}, 'key': "KEY", "name": "A name",
                    'reviewers': [], 'version': 'na', 'slug': 'theslug',
                    'project': {'key': 'KEY'}, 'user': {'slug': "~user"},
                    'title': "Some Title", 'label': 'something'
                }
                testobj = testclass(self.bb_objectify(resource_dict), self.bb)
                if hasattr(testobj, '_parent_slug'):
                    testobj._parent_slug = 'TEST'
                if hasattr(testobj, '_parent_project_key'):
                    testobj._parent_project_key = 'PROJ'
                self.assertIsInstance(str(testobj), str)
                self.assertIsInstance(repr(testobj), str)

                method = getattr(testobj, method_name)
                results = method(*args)

                self.assertTrue(
                    any([
                        self.mock_session.get.called,
                        self.mock_session.put.called,
                        self.mock_session.post.called,
                        self.mock_session.delete.called
                    ])
                )

    def test_coverage_instantitate_objects(self):
        cases = [
            (resources.BitbucketObject, {}),
            (resources.ProjectContextBitbucketObject, {}),
            (resources.RepoContextBitbucketObject, {}),
            (resources.BaseRefResourceObject, {"id": "deadbeef"}),
            (resources.BranchResource, {"id": "deadbeef"}),
            (resources.BuildStatisticResource, {}),
            (resources.BuildStatusResource, {"key": "KEY", "state": "MERGED"}),
            (resources.ChangesResource, {"path": {"toString": "/a/path"}}),
            (resources.CommitResource, {"id": "deadbeef"}),
            (resources.FileDiffResource, {"hunks": []}),
            (resources.HookResource, {"details": {"key": "somekey"}}),
            (resources.ParticipantResource, {"user": {"name": "username"}}),
            (resources.ProjectAuditResource, {}),
            (resources.ProjectResource, {'key': "KEY"}),
            (resources.PullRequestResource, {'id': 123, 'reviewers': []}),
            (resources.PullRequestContextBitbucketObject, {'id': 123}),
            (resources.PullRequestActivityResource, {'id': 123, 'action': 'COMMENT'}),
            (resources.RepositoryAuditResource, {}),
            (resources.RepositoryResource, {"slug": "name", "project": {'key': "KEY"}, 'id': 123}),
            (resources.SettingsResource, {}),
            (resources.SSHKeyResource, {"label": "label"}),
            (resources.TagResource, {"id": "ref/heads/tag"}),
            (resources.TaskResource, {"id": 123}),
            (resources.UserResource, {"slug": "username"}),
            (resources.UserAccessToken, {'id': 123, 'name': 'name'}),
            (resources.CodeInsightReport, {'key': 'somekey', 'title': 'title'}),
            (resources.WebhookResource, {'id': 123}),
        ]
        for testclass, resource_dict in cases:
            with self.subTest(testclass.__name__):
                testobj = testclass(self.bb_objectify(resource_dict), self.bb)
                if hasattr(testobj, '_parent_slug'):
                    testobj._parent_slug = 'TEST'
                if hasattr(testobj, '_parent_project_key'):
                    testobj._parent_project_key = 'PROJ'
                self.assertIsInstance(str(testobj), str)
                self.assertIsInstance(repr(testobj), str)
                dir(testobj)
                self.assertEqual(testobj, testobj)
                self.assertNotEqual(testobj, object())
                self.assertIs(testobj.server, self.bb)
                testobj._update(testobj)
                self.assertNotIn("notin", testobj)
                with self.assertRaises(RuntimeError):
                    testobj._update(object())
                # __iter__
                try:
                    for o in testobj:
                        pass
                except TypeError:
                    pass
                # __int__
                try:
                    self.assertIsInstance(int(testobj), int)
                except TypeError:
                    pass
                # __get_item__
                with self.assertRaises(KeyError):
                    testobj['notin']

    def test_coverage_repo_related_properties(self):
        cases = [
            (resources.BaseRefResourceObject, 'commit'),
            (resources.ProjectResource, 'url'),
            (resources.ProjectContextBitbucketObject, 'project'),
            (resources.RepoContextBitbucketObject, 'repo'),
            (resources.RepoContextBitbucketObject, 'compound_key'),
            (resources.BaseRefResourceObject, 'commit'),
            (resources.BaseRefResourceObject, 'name'),
            (resources.BuildStatusResource, 'passed'),
            (resources.BuildStatusResource, 'failed'),
            (resources.BuildStatusResource, 'in_progress'),
            (resources.CommitResource, 'authorTimestamp'),
            (resources.CommitResource, 'commit'),
            (resources.HookResource, 'name'),
            (resources.HookResource, 'key'),
            (resources.ParticipantResource, 'is_author'),
            (resources.ParticipantResource, 'is_reviewer'),
            (resources.PullRequestResource, 'url'),
            (resources.PullRequestResource, 'compound_key'),
            (resources.PullRequestResource, 'participants'),
            (resources.PullRequestResource, 'declined'),
            (resources.PullRequestResource, 'merged'),
            (resources.PullRequestResource, 'createdDate'),
            (resources.PullRequestResource, 'closedDate'),
            (resources.PullRequestResource, 'updatedDate'),
            (resources.PullRequestResource, 'can_merge'),

            (resources.RepositoryResource, 'compound_key'),
            (resources.RepositoryResource, 'ssh_url'),
            (resources.RepositoryResource, 'url'),
            (resources.RepositoryResource, 'lfs_enabled'),
            (resources.UserResource, 'project_key'),
            (resources.UserAccessToken, 'token'),
            (resources.CodeInsightReport, 'report_key'),
            (resources.CodeInsightReport, 'data'),


        ]
        for testclass, attr_name in cases:
            with self.subTest(f"{testclass}.{attr_name})"):
                self.mock_session.reset_mock()

                resource_dict = {'id': 123, 'latestCommit': "beef", 'key': "PROJ",
                    "slug": "SLUG",
                    'displayId': 'name', 'state': "FAILED", "authorTimestamp": 1556236159000,
                    "createdDate": 1556236159000,
                    "closedDate": 1556236159000,
                    "updatedDate": 1556236159000,
                    'reviewers': [],
                    'details': {'name': "name", "key": "KEY"}, "role": "AUTHOR",
                    "links": {"self": [{"href": "http://...."}], "clone": [
                        {'name': "ssh", 'href': "ssh://..."}
                    ]},
                    "project": {'key': "KEY"}, 'token': "..."
                }
                testobj = testclass(self.bb_objectify(resource_dict), self.bb)
                if hasattr(testobj, '_parent_slug'):
                    testobj._parent_slug = 'TEST'
                if hasattr(testobj, '_parent_project_key'):
                    testobj._parent_project_key = 'PROJ'

                results = getattr(testobj, attr_name)
                results = getattr(testobj, attr_name) # do it twice for caches
