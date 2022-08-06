"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

Bitbucket Server / Datacenter API Wrapper
"""
from os.path import splitext, exists

from bitbucketserver import resources
from bitbucketserver.connection import decode_json, raise_for_errors, BitbucketServerException
from bitbucketserver.connection import BitbucketConnection

import logging

log = logging.getLogger(__name__)

# TODO: implement jira-dev related endpoints
# https://confluence.atlassian.com/bitbucketserverkb/the-number-of-pull-requests-or-branches-from-bitbucket-server-dc-differs-between-jira-development-panel-overview-and-details-1041078861.html

# API Changelog: https://developer.atlassian.com/server/bitbucket/reference/api-changelog/


class APIVersions(object):
    """Class for holding API version information."""

    def __init__(self):
        self.core = 'rest/api/1.0/'
        self.permissions = 'rest/branch-permissions/2.0/'
        self.branch_utils = 'rest/branch-utils/1.0/'
        self.build_status = 'rest/build-status/1.0/'
        self.git = 'rest/git/1.0/'
        self.ssh = 'rest/ssh/1.0/'
        self.keys = 'rest/keys/1.0/'
        self.audit = 'rest/audit/1.0/'
        self.mirroring = 'rest/mirroring/1.0/'
        self.refsync = 'rest/sync/1.0/'
        self.shortcuts = 'rest/repository-shortcuts/latest/'
        self.access_tokens = 'rest/access-tokens/1.0/'
        self.insights = 'rest/insights/1.0/'
        self.jira = 'rest/jira/1.0/'

        # Internal
        self.git_lfs = 'rest/git-lfs/admin/'
        self.jira_integration = 'rest/jira-integration/latest/'

    def __str__(self):
        return str(self.__dict__)


class BitbucketServer(object):
    """
    BitbucketServer is a wrapper for the Stash/Bitbucket Server REST API.

    Args:
        url (str): full URL for the server to access
        basic_auth (tuple): a tuple of username, password.
        bearer_token (str): the personal access token string
        api_versions (optional APIVersions): object with attributes for various API access versions.

            For anonymous login, do not provide any auth methods.
    Usage:

        import bitbucketserver
        bb = bitbucketserver.BitbucketServer(url='https://bitbucket.example.com/',
                                             basic_auth=('username', 'password'))
        myrepo = bb.repo('~myusername', 'my-repo')

    """
    # Partially Supported APIs
    # https://developer.atlassian.com/static/rest/bitbucket-server/4.3.1/bitbucket-rest.html
    # https://developer.atlassian.com/static/rest/stash/3.11.3/stash-branch-permissions-rest.html
    # https://developer.atlassian.com/static/rest/stash/latest/stash-branch-utils-rest.html
    # https://developer.atlassian.com/static/rest/stash/latest/stash-build-integration-rest.html

    # Others:
    # https://developer.atlassian.com/static/rest/stash/latest/

    def __init__(self, url, basic_auth=None, bearer_token=None,
            api_versions=None, headers=None, ssl_verify=True):
        if api_versions is None:
            api_versions = APIVersions()
        self.api_versions = api_versions
        self._username = None
        log.debug("API Version: %s", self.api_versions.core)
        self.conn = BitbucketConnection(
            url=url,
            bearer_token=bearer_token,
            basic_auth=basic_auth,
            api_versions=api_versions,
            headers=headers,
            verify=ssl_verify
        )
        try:
            self._server_info = self.server_info()
            self._server_version = tuple(int(n) for n in (self._server_info['version'].split(".")))
        except (ValueError, KeyError):
            log.exception("error parsing server info")
            raise
        except BitbucketServerException:
            raise
        except Exception:
            log.exception("error connecting to url %s", url)
            raise ValueError(f"Unable to connect to '{url}'. Please verify the URL")

    @property
    def username(self):
        if self._username is None:
            if not self.conn.last_response:
                self.server_info()
            self._username = self.conn.last_response.headers.get('X-AUSERNAME', None)
        return self._username

    def test_connection(self):
        log.debug("testing connection...")
        return self.conn.test()

    def server_info(self):
        """Get server information.

        Returns:
            dictionary of server information.
        """
        log.info('getting server info')
        uri = 'application-properties'
        return self.conn.get(uri)

    def users(self, filters=None, break_point=None):
        """Get all users.

        Args:
            filters (dict): dictionary of key value pairs to filter on
            break_point (int): approximate number of users to retrieve

        Returns:
            list of UserResource
        """
        log.info("getting users")
        uri = 'users'
        return [resources.UserResource(r, self) for r in self.conn.get_paged(uri, parameters=filters, break_point=break_point)]

    def groups(self, filter=None):
        """Retrieve a list of available group names.

        Args:
            filter (str, optional): Optionally filter by group name.
        """
        log.info("getting groups")
        uri = 'groups'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def group_membership(self, group_name):
        """Get a list of users who are members of the given group.

        Args:
            group_name (str): group name
        """
        return self.users(filters={'group': group_name})

    def user(self, username):
        """Get user info from the server.

        Args:
            username (str): The username.

        Returns:
            resources.UserResource

        Raises:
            HTTPError: if `username` is not found.
        """
        log.info("getting user '%s'", username)
        uri = f'users/{username}'
        return resources.UserResource(self.conn.get(uri), self)

    def current_user(self):
        """Gets the current logged in user.

        Returns:
            resources.UserResource
        """
        return self.user(self.username)

    def update_user_avatar(self, username, filename):
        """Update a user's avatar. Image should be square, 1024x1024 maximum size.

        Args:
            username (str): the username to update
            filename (str): the filename to open

        Returns:
            None
        """
        uri = f'users/{username}/avatar.png' # .png even if we're dealing with jpgs
        with open(filename, 'rb') as fp:
            _, ext = splitext(filename)
            if ext[0] == '.': # remove . if it gave us one
                ext = ext[1:]
            # TODO: we should use python-magic
            files = {'avatar': (filename, fp, 'image/{0}'.format(ext), {'X-Atlassian-Token': 'no-check'})}
            # This endpoint requires skipping the XSRF check, so supply the requisite header...
            self.conn.post(uri, files=files, headers={'X-Atlassian-Token': 'no-check'})

    def download_user_avatar(self, username, filename):
        """Download the given user's avatar image. This is always a PNG file.

        Note: this will *always* download content, even if the user doesn't exist.
        Bitbucket just returns the default avatar rather than throw an error.

        Args:
            username (str): the username
            filename (str): the filename to save the avatar to.

        Returns:
            None
        """
        # This isn't actually an API endpoint, so we need to fudge the base:
        # actual URL is <server>/users/<username>/avatar.png
        # This will always return content, even if the user doesn't exist.
        response = self.conn.get_response(f'users/{username}/avatar.png', base='')
        raise_for_errors(response)
        with open(filename, 'wb') as fp:
            fp.write(response.content)

    def projects(self, name=None, permission=None):
        """Get a list of all projects from the server.

        Args:
            break_point (int): approximate number of projects to retrieve

        Returns:
            list: List of resources.ProjectResource
        """
        log.info('getting list of projects')
        uri = 'projects'
        params = {}
        if name:
            params['name'] = name
        if permission:
            params['permission'] = permission
        return [resources.ProjectResource(r, self) for r in self.conn.get_paged(uri, parameters=params)]

    def project(self, project):
        """Get information on the given project.

        Args:
            project (str): The requested project key.

        Returns:
            resources.ProjectResource

        Raises:
            HTTPError: if `project` is not found.
        """
        log.info("getting project '%s'", project)
        uri = f'projects/{project}'
        return resources.ProjectResource(self.conn.get(uri), self)

    def create_project(self, project_key, project_name, description=None):
        """Creates a new project.

        Args:
            project_key (str): The desired key for hte new project
            project_name (str): The name of the new project.
            description (Optional[str]): The project's description.

        Returns:
            resources.ProjectResource

        Raises:
            HTTPError: if there was an error creating the project.
        """
        log.info("creating project '%s' (%s)", project_name, project_key)
        uri = 'projects'
        project = {
            'key': project_key,
            'name': project_name,
        }
        if description:
            project['description'] = description
        return resources.ProjectResource(decode_json(self.conn.post(uri, json=project)), self)

    def delete_project(self, project):
        """Deletes the given project.

        Args:
            project (str): the project to delete

        Returns:
            None
        """
        log.info("deleting project '%s'", project)
        uri = f'projects/{project}'
        response = self.conn.delete(uri)
        if response.status_code != 204:
            raise Exception("Delete failed:", response.reason)

    def project_group_permissions(self, project, filter=None):
        """Get the group permissions for the given project.

        Args:
            project (str): the project key
            filter (str): group name to filter by

        Returns:
            list: the list of group permissions for the project
        """
        uri = f'projects/{project}/permissions/groups'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def project_group_no_permissions(self, project, filter=None):
        """Get a list of groups that have no permissions for the given project.

        Args:
            project (str): the project key
            filter (str): group name to filter by

        Returns:
            list: list of groups
        """
        uri = f'projects/{project}/permissions/groups/none'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def set_project_group_permission(self, project, group, permission):
        """Add or set group permissions for a project.

        Args:
            project (str): the project key
            group (str): the group name
            permission (str): the permission to add
                PROJECT_READ, PROJECT_WRITE, PROJECT_ADMIN

        Returns:
            None
        """
        uri = f'projects/{project}/permissions/groups'
        params = {
            'permission': permission,
            'name': group,
        }
        self.conn.put(uri, parameters=params)

    def delete_project_group_permission(self, project, group):
        """Delete the given group's permissions from the project.

        Args:
            project (str): the project key
            group (str): the group name

        Returns:
            None
        """
        uri = f'projects/{project}/permissions/groups'
        params = {
            'name': group
        }
        self.conn.delete(uri, parameters=params)

    def project_user_permissions(self, project, filter=None):
        """Get the user permissions for the given project.

        Args:
            project (str): the project key
            filter (str): user name to filter by

        Returns:
            list: the list of user permissions for the project
        """
        uri = f'projects/{project}/permissions/users'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def project_user_no_permissions(self, project, filter=None):
        """Get a list of users that have no permissions for the given project.

        Args:
            project (str): the project key
            filter (str): user name to filter by

        Returns:
            list: list of users
        """
        uri = f'projects/{project}/permissions/users/none'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def set_project_user_permission(self, project, user, permission):
        """Add or set user permissions for a project

        Args:
            project (str): the project key
            user (str): the user name
            permission (str): the permission to add

        Returns:
            None
        """
        uri = f'projects/{project}/permissions/users'
        params = {
            'permission': permission,
            'name': user,
        }
        self.conn.put(uri, parameters=params)

    def delete_project_user_permission(self, project, user):
        """Delete the given user's permissions from the project.

        Args:
            project (str): the project key
            user (str): the user name

        Returns:
            None
        """
        uri = f'projects/{project}/permissions/users'
        params = {
            'name': user
        }
        self.conn.delete(uri, parameters=params)

    def project_default_permission(self, project, project_permission):
        """Returns a bool of the given default permission is the level specified.

        Args:
            project (str): the project key
            project_permission (str): the project permission
                PROJECT_READ, PROJECT_WRITE

        Returns:
            bool: if the given permission is allowed or not
        """
        uri = f'projects/{project}/permissions/{project_permission}/all'
        response = self.conn.get(uri)
        return response.get("permitted")

    def set_project_default_permission(self, project, project_permission, allow):
        """Update the default permissions for the given permission level.

        Args:
            project (str): the project key
            project_permission (str): the permission level
                PROJECT_READ, PROJECT_WRITE
            allow (bool): true to grant, false to revoke
        """
        uri = f'projects/{project}/permissions/{project_permission}/all'
        content = {'permitted': allow}
        params = {'allow': allow} # ...BB apparently needs this, too.
        self.conn.post(uri, parameters=params, json=content)

    def project_audit(self, project, break_point=None):
        """Retrieves the audit events for the given project.

        Args:
            project (str): the project key
            break_point (int): approximate number of records to retrieve

        Returns:
            list: the projects' audit
        """
        uri = f'projects/{project}/events'
        return [resources.ProjectAuditResource(r, self, project) for r in self.conn.get_paged(uri, base=self.api_versions.audit, break_point=break_point)]

    def search_repos(self, repo_name=None, project_name=None, break_point=None):
        """Search for repos.

        Args:
            repo_name (optional str): repo name to search for (case insensitive)
            project_name (optional str): project name to search by
            break_point (int): approximate number of repos to retrieve

        Returns:
            list: list of matching resources.RepositoryResources
        """
        uri = 'repos'
        params = {}
        if repo_name:
            params['name'] = repo_name
        if project_name:
            params['projectname'] = project_name
        log.info("searching for repos: %s", params)
        return [resources.RepositoryResource(r, self) for r in self.conn.get_paged(uri, parameters=params, break_point=break_point)]

    def repos(self, project):
        """Get all visible repos in the given project_key.

        Args:
            project (str): The project to get repos from.

        Returns:
            list of resources.RepositoryResource

        Raises:
            HTTPError: if the project_key could not be found.
        """
        uri = f'projects/{project}/repos'
        log.info("getting repos for project '%s'", project)
        return [resources.RepositoryResource(r, self) for r in self.conn.get_paged(uri)]

    def repo(self, project, slug):
        """Gets the given repo from the given project.

        Args:
            project (str): The project the repo is in.
            slug (str): The slug identifying the desired repo.

        Returns:
            resources.RepositoryResource

        Raises:
            HTTPError: if the repo cannot be found.
        """
        log.info("getting repo %s/%s", project, slug)
        uri = f'projects/{project}/repos/{slug}'
        return resources.RepositoryResource(self.conn.get(uri), self)

    def repo_by_id(self, repo_id):
        """Gets the repo object from the repository ID.

        Args:
            repo_id (int): the repository ID

        Returns:
            resources.RepositoryResource

        Raises:
            HTTPError: if the repo cannot be found.
        """
        log.info("getting repo from key %i", repo_id)
        # This is repurposing the mirroring API, but Atlassian doesn't give any other
        # REST endpoint for the repo by ID.
        uri = f'repos/{repo_id}'
        return resources.RepositoryResource(self.conn.get(uri, base=self.api_versions.mirroring), self)

    def create_repo(self, project, repo_name, description=None, forkable=True, public=False):
        """Create a new repo in the given project.

        Args:
            project (str): The project key where the new repo will be located.
                When creating a user repo, supply `~username` as the project.
            repo_name (str): The plain English name of the new repo.
                Bitbucket will auto-create the repo slug.
            description (Optional [str]): repository description.
            forkable (Optional [bool]): Flag for if the repo is forkable or not.
                Defaults to True.
            public (Optional [bool]): Flag for if the repo is publically available.
                Defaults to False.

        Returns:
            resources.RepositoryResource

        Raises:
            HTTPError: if the repo could not be created.
        """
        uri = f'projects/{project}/repos'
        payload = {
            'name': repo_name,
            'scmId': 'git',
            'forkable': forkable,
            'public': public,
            'description': description
        }
        log.info("creating new repo '%s' in project '%s'", repo_name, project)
        log.debug(payload)
        return resources.RepositoryResource(decode_json(self.conn.post(uri, json=payload)), self)

    def delete_repo(self, project, slug):
        """Delete the given repo.
        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to delete.

        Returns:
            bool: True if successfully deleted

        Raises:
            HTTPError: if the delete failed.
        """
        uri = f'projects/{project}/repos/{slug}'
        log.info("deleting repo: %s", uri)
        resp = self.conn.delete(uri)
        if resp.status_code != 202:
            raise Exception("Delete failed:", resp.reason)
        return True

    def update_repo(self, project, slug, description=None, new_name=None, forkable=None, public=None):
        """Update the repo's settings.

        Args:
            project: the project for the given repo
            slug: the given repo slug
            description (Optional [str]): optional, update the repo description
            new_name (str): optional, set a new name for the repo
            forkable (bool): optional, set the forkable flag
            public (bool): optional, set the public flag

        Returns:
            resources.RepositoryResource: the updated repo
        """
        uri = f'projects/{project}/repos/{slug}'
        payload = {}
        # Only modify attributes that we were asked to:
        if description is not None:
            payload['description'] = description
        if new_name is not None:
            payload['name'] = new_name
        if public is not None:
            payload['public'] = public
        if forkable is not None:
            payload['forkable'] = forkable
        if not payload:
            raise Exception("no modification specified") # TODO: silently pass?
        log.info("updating repo: %s: %s", uri, payload)
        return resources.RepositoryResource(decode_json(self.conn.put(uri, json=payload)), self)

    def repo_git_lfs_status(self, project, slug):
        """Get a repo's git-lfs status.

        Args:
            project: the project key
            slug: the repo slug

        Returns:
            bool: if git lfs is enabled or not
        """
        # TODO: this is an ugly internal API. Update when https://jira.atlassian.com/browse/BSERV-8935
        # gets implemented...
        # ...that's not going happen.
        uri = f'projects/{project}/repos/{slug}/enabled'
        response = self.conn.get_response(uri, base=self.api_versions.git_lfs)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            response.raise_for_status()

    def enable_git_lfs_in_repo(self, project, slug):
        """Enable git-lfs for the given repo.

        Args:
            project: the project key
            slug: the repo slug

        Returns:
            None
        """
        uri = f'projects/{project}/repos/{slug}/enabled'
        self.conn.put(uri, base=self.api_versions.git_lfs)

    def disable_git_lfs_in_repo(self, project, slug):
        """Disable git-lfs for the given repo.

        Args:
            project: the project key
            slug: the repo slug

        Returns:
            None
        """
        uri = f'projects/{project}/repos/{slug}/enabled'
        self.conn.delete(uri, base=self.api_versions.git_lfs)

    def move_repo(self, project, slug, new_project, new_name=None):
        """Move the repo to a new project.

        Args:
            project: repo's current location
            slug: repo's current slug
            new_project: project to move the repo to
            new_name (optional str): optionally rename the repo

        Returns:
            resources.RepositoryResource: the updated repo
        """
        uri = f'projects/{project}/repos/{slug}'
        payload = {
            'project': {'key': new_project},
        }
        if new_name is not None:
            payload['name'] = new_name
        log.info("moving repo: %s: %s", uri, payload)
        return resources.RepositoryResource(decode_json(self.conn.put(uri, json=payload)), self)

    def fork_repo(self, project, slug, fork_name, destination_project=None):
        """Fork the given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to fork.
            fork_name (str): The plain English name of the forked repo.
            destination_project (Optional [str]): The destination project to put the fork.
                Defaults to None, which places the fork in the current user's personal repos.

        Returns:
            resources.RepositoryResource: the forked repo

        Raises:
            HTTPError: if the fork failed.
        """
        uri = f'projects/{project}/repos/{slug}'
        payload = {'name': fork_name}
        if destination_project:
            payload['project'] = {'key': destination_project}
        log.info("forking repo: %s/%s", project, slug)
        return resources.RepositoryResource(decode_json(self.conn.post(uri, json=payload)), self)

    def repo_forks(self, project, slug, project_key=None):
        """Get a list of forks from the given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to list forks.
            project_key (optional str): limit returned repos to the given project


        Returns:
            list: List of resources.RepositoryResource that were forked from the given repo.

        Raises:
            HTTPError: if the given repo could not be found.
        """
        uri = f'projects/{project}/repos/{slug}/forks'
        params = {}
        if project_key:
            params['projectKey'] = project_key
        log.info("getting list of forks for: %s/%s", project, slug)
        return [resources.RepositoryResource(r, self) for r in self.conn.get_paged(uri, parameters=params)]

    def related_repos(self, project, slug, project_key=None):
        """Get a list of repos related to the given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to find relations of.
            project_key (optional str): limit returned repos to the given project

        Returns:
            list: List of resources.RepositoryResource that are directly related (via forking, etc)
                to the given repo.

        Raises:
            HTTPError: if the given repo could not be found.
        """
        uri = f'projects/{project}/repos/{slug}/related'
        params = {}
        if project_key:
            params['projectKey'] = project_key
        log.info("getting repos related to: %s/%s", project, slug)
        return [resources.RepositoryResource(r, self) for r in self.conn.get_paged(uri, parameters=params)]

    def repo_group_permissions(self, project, slug, filter=None):
        """Get the group permissions for the given repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            filter (str): group name to filter by

        Returns:
            list: the list of group permissions for the project
        """
        uri = f'projects/{project}/repos/{slug}/permissions/groups'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def repo_group_no_permissions(self, project, slug, filter=None):
        """Get a list of groups that have no permissions for the given repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            filter (str): group name to filter by

        Returns:
            list: list of groups
        """
        uri = f'projects/{project}/repos/{slug}/permissions/groups/none'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def set_repo_group_permission(self, project, slug, group, permission):
        """Add or set group permissions for a repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            group (str): the group name
            permission (str): the permission to add

        Returns:
            None
        """
        uri = f'projects/{project}/repos/{slug}/permissions/groups'
        params = {
            'permission': permission,
            'name': group,
        }
        self.conn.put(uri, parameters=params)

    def delete_repo_group_permission(self, project, slug, group):
        """Delete the given group's permissions from the repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            group (str): the group name

        Returns:
            None
        """
        uri = f'projects/{project}/repos/{slug}/permissions/groups'
        params = {
            'name': group
        }
        self.conn.delete(uri, parameters=params)

    def repo_user_permissions(self, project, slug, filter=None):
        """Get the user permissions for the given repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            filter (str): user name to filter by

        Returns:
            list: the list of user permissions for the project
        """
        uri = f'projects/{project}/repos/{slug}/permissions/users'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def repo_user_no_permissions(self, project, slug, filter=None):
        """Get a list of users that have no permissions for the given repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            filter (str): user name to filter by

        Returns:
            list: list of users
        """
        uri = f'projects/{project}/repos/{slug}/permissions/users/none'
        params = {}
        if filter:
            params['filter'] = filter
        return self.conn.get_paged(uri, parameters=params)

    def set_repo_user_permission(self, project, slug, user, permission):
        """Add or set user permissions for a repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            user (str): the user name
            permission (str): the permission to add

        Returns:
            None
        """
        uri = f'projects/{project}/repos/{slug}/permissions/users'
        params = {
            'permission': permission,
            'name': user,
        }
        self.conn.put(uri, parameters=params)

    def delete_repo_user_permission(self, project, slug, user):
        """Delete the given user's permissions from the repo.

        Args:
            project (str): the project key
            slug (str): the repo slug
            user (str): the user name

        Returns:
            None
        """
        uri = f'projects/{project}/repos/{slug}/permissions/users'
        params = {
            'name': user
        }
        self.conn.delete(uri, parameters=params)

    def repo_audit(self, project, slug):
        """Get a list of audit events for the given repo.

        https://confluence.atlassian.com/bitbucketserver/audit-events-in-bitbucket-server-776640423.html

        Args:
            project (str): the project key
            slug (str): the repository slug

        Returns:
            list: the audit events for the repository.
        """
        uri = f'projects/{project}/repos/{slug}/events'
        return [resources.RepositoryAuditResource(r, self, project, slug) for r in self.conn.get_paged(uri, base=self.api_versions.audit)]

    def repo_changes(self, project, slug, until='HEAD', since=None):
        """Get a list of changes to the related repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of changes from.
            until (Optional[str]): The commit hash or ref to retrieve changes before (inclusive).
                Default: HEAD
            since (Optional[str]): The commit hash or ref to retrieve changes after (exclusive).

        Returns:
            list: list of resource.ChangesResources
        """
        uri = f'projects/{project}/repos/{slug}/changes'
        params = {
            'until': until,
        }
        if since:
            params['since'] = since
        log.info("getting list of changes for: %s/%s", project, slug)
        log.info(params)
        return [resources.ChangesResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params)]

    def file_diff(self, project, slug, path, revision, since=None, ignore_whitespace=False, context_lines=10):
        """Arbitrarily diff an individual file.

        Args:
            project (str): the project key
            slug (str): the repo slug
            path (str): path to the file to diff
            revision (str): the until revision
            since (optional str): the since revision
                Default's to the parent of the given revision.
            ignore_whitespace (optional bool): whether or not to ignore whitespace
                Defaults to False.
            context_lines (optional int): the number of context lines to include.
                Defaults to 10 lines.

        Returns:
            list of FileDiffResource objects
        """
        # this will probably be paged someday
        uri = f'projects/{project}/repos/{slug}/diff/{path}'
        params = {
            'until': revision,
            'contextLines': context_lines,
        }
        if ignore_whitespace:
            params['whitespace'] = 'ignore-all'
        if since:
            params['since'] = since
        response = self.conn.get(uri, parameters=params)
        return [resources.FileDiffResource(r, self, project, slug) for r in response['diffs']]

    def compare_changes(self, project, slug, from_ref=None, to_ref=None, from_repo=None):
        """Return a list of changes from comparing two refs.

        Args:
            project: the project key
            slug: the repo slug
            from_ref: the source commit (can be a partial/full commit ID or qualified/unqualified ref name)
            to_ref: the target commit (can be a partial/full commit ID or qualified/unqualified ref name)
            from_repo: optional repo ID (integer) or string of 'proj_key/slug'

        Returns:
            list of changes objects
        """
        uri = f'projects/{project}/repos/{slug}/compare/changes'
        params = {}
        if from_ref:
            params['from'] = from_ref
        if to_ref:
            params['to'] = to_ref
        if from_repo:
            params['fromRepo'] = str(from_repo)
        return [resources.ChangesResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params)]

    def repo_commits(self, project, slug, path=None, since=None, until=None, break_point=None):
        """Get a list of commits from the given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of commits from.
            path (Optional[str]): An optional path to filter commits by.
            since (Optional[str]): The commit hash or ref to retrieve commits after (exclusive).
            until (Optional[str]): The commit hash or ref to retrieve commits before (inclusive).
            break_point (int): approximate number of commits to retrieve

        Returns:
            list: List of resources.CommitResource for the given repo.

        Raises:
            HTTPError: if the given repo could not be found.
        """
        uri = f'projects/{project}/repos/{slug}/commits'
        params = {}
        if path:
            params['path'] = path
        if since:
            params['since'] = since
        if until:
            params['until'] = until
        log.info("getting commits for: %s/%s", project, slug)
        return [resources.CommitResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params, break_point=break_point)]

    def repo_commit(self, project, slug, commit_hash, path=None):
        """Return the commit with the given hash.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of commits from.
            commit_hash (str): full SHA1 of the commit
            path (optional str): optional path to filter commits by.
                If not for the specified commit, this option will then return the
                first instance where path matches.

        Returns:
            resources.CommitResource
        """
        uri = f'projects/{project}/repos/{slug}/commits/{commit_hash}'
        params = {}
        if path:
            params['path'] = path
        log.info("getting commit '%s' from %s/%s", commit_hash, project, slug)
        return resources.CommitResource(self.conn.get(uri, parameters=params), self, project, slug)

    def repo_commit_changes(self, project, slug, commit_hash, since=None, withComments=True):
        """Retrieve the changes made in the specified commit.

        If the given commit has a single ancestor, it will by default return the changes since then.
        If there is more than one parent, the parent must be specified or 0 changes are returned.

        Using CommitResource.changes() may be simpler.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of commits from.
            commit_hash (str): full SHA1 of the commit
            since (optiona str): commit of the historical commit to reference against
            withComments (optional bool): something about comment counts

        Returns:
            list: resources.CommitResource
        """
        uri = f'projects/{project}/repos/{slug}/commits/{commit_hash}/changes'
        params = {}
        if since:
            params['since'] = since
        if not withComments: # True is the default
            params['withComments'] = False
        return [resources.ChangesResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params)]

    def commit_pull_requests(self, project, slug, commit_hash):
        """Return the pull requests associated with the given commit hash.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of commits from.
            commit_hash (str): full SHA1 of the commit

        Returns:
            list: list of resources.PullRequestResource
        """
        uri = f'projects/{project}/repos/{slug}/commits/{commit_hash}/pull-requests'
        return [resources.PullRequestResource(pr, self, project, slug) for pr in self.conn.get_paged(uri)]

    def repo_commit_stats(self, project, slug, path=None, since=None, until=None):
        """Return the number of authors and commits of a given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of commits from.
            path (Optional[str]): An optional path to filter commits by.
            since (Optional[str]): The commit hash or ref to retrieve commits after (exclusive).
            until (Optional[str]): The commit hash or ref to retrieve commits before (inclusive).
        Returns:
            (int) author count, (int) total count
        """
        uri = f'projects/{project}/repos/{slug}/commits'
        params = {'withCounts': True}
        if path:
            params['path'] = path
        if since:
            params['since'] = since
        if until:
            params['until'] = until
        log.info("getting repo commit stats for: %s/%s", project, slug)
        content = self.conn.get(uri, parameters=params)
        return content['authorCount'], content['totalCount']

    def commit_branches(self, project, slug, commit_hash):
        """Return the branches associated with the given commit.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to get a list of commits from.
            commit_hash (str): full SHA1 of the commit

        Returns:
            list: list of resources.BranchResources associated with the given commit
        """
        uri = f'projects/{project}/repos/{slug}/branches/info/{commit_hash}'
        log.info("getting branches for commit '%s' in %s/%s", commit_hash, project, slug)
        return [resources.BranchResource(r, self, project, slug) for r in self.conn.get_paged(uri,
                                                                                        base=self.api_versions.branch_utils)]

    def file_contents(self, project, slug, filepath, at=None):
        """Returns the contents of a file as a list.

        Args:
            project:
            slug:
            filepath: full repo-relative path to the file.
                Use linux path separators.
            at: hash or ref ID for where to get the file contents.

        Returns:
            list: list of strings for the file contents

        Raises:
            Exception if file is a binary file.
        """
        # TODO: add converting of windows\file\paths, just in case.
        uri = f'projects/{project}/repos/{slug}/browse'
        if filepath.startswith('/'):
            uri += filepath
        else:
            uri += '/' + filepath
        params = {}
        if at:
            params['at'] = at
        log.info("getting file contents: %s", uri)
        try:
            rows = self.conn.get_paged(uri, parameters=params, key='lines')
        except KeyError as ke:
            # Binary files give back file info, no lines entry.
            if 'lines' in str(ke) and self.conn.last_response.json()['binary']: # TODO: not thread safe
                raise Exception('cannot retrieve binary file contents')
            else: # some other key error, raise it
                raise
        # each line is a dictionary: {'text': "..."}, so pull that out:
        return [r['text'] for r in rows]

    def repo_files(self, project, slug, path=None, at=None):
        """Returns a list of strings for the files in the repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo.
            path (str): directory path to get file list.
            at (str): hash or ref ID for where to get the file list

        Returns:
            list: list of strings of repo relative paths and filenames.
        """
        uri = f'projects/{project}/repos/{slug}/files'
        if path:
            if path.startswith('/'):
                uri += path
            else:
                uri += '/' + path
        params = {}
        if at:
            params['at'] = at
        log.info("getting filelist for: %s/%s/%s", project, slug, path)
        return self.conn.get_paged(uri, parameters=params)

    def raw_file(self, project, slug, path, at=None):
        """Get the given file's contents.
        WARNING: heavy use of this may cause performance issues for the server.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo slug.
            path (str): the file path to get.
            at (str, optional): Defaults to None. The ref or hash to get the file at.

        Returns:
            bytes: the raw file contents
        """
        uri = f"projects/{project}/repos/{slug}/raw/{path}"
        params = {}
        if at:
            params['at'] = at
        response = self.conn.get_response(uri, parameters=params, base='')
        raise_for_errors(response)
        return response.content

    def create_branch(self, project, slug, branch_name, start_ref, message=None):
        """Create a new branch tag.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to branch.
            branch_name (str): The name of the new branch.
            start_ref (str): The ref where the branch tag should go.
            message (Optional [str]): The optional commit message for creating the branch.

        Returns:
            resources.BranchResource: the new branch.

        Raises:
            HTTPError: if the branch creation failed.
        """
        uri = f'projects/{project}/repos/{slug}/branches'
        payload = {
            'name': branch_name,
            'startPoint': start_ref,
        }
        if message: # TODO: this might be required; set a default?
            payload['message'] = message
        log.info("creating branch '%s' in repo '%s/%s' at %s", branch_name, project, slug, start_ref)
        # Note: the core API URI base does not work for *creating* branches, even though it says it does
        # TODO: check this ^ in a newer version of BitbucketServer
        return resources.BranchResource(decode_json(self.conn.post(uri, json=payload, base=self.api_versions.branch_utils)),
                                        self, project, slug)

    def repo_branches(self, project, slug, filterText=None, base=None, details=False, alphabetical=False, break_point=None):
        """Get a list of branches associated with the given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo from which to get branch information.
            filterText (Optional [str]): Text to match on.
            base (Optional [str]): base branch or tag to compare each branch to. Defaults to None.
            details (Optional [bool]): whether to retrieve plugin-provided metadata about each branch.
                Defaults to False.
            alphabetical (Optional [bool]): List branches alphabetically instead of in order.
            break_point (Optional [int]): approximate number of branches to retrieve

        Returns:
            list: List of resources.BranchResource containing branch information.
        """
        params = {}
        if base:
            params['base'] = base
        if details:
            params['details'] = details
        if filterText:
            params['filterText'] = filterText
        if alphabetical:
            params['orderBy'] = 'ALPHABETICAL'
        uri = f'projects/{project}/repos/{slug}/branches'
        log.info("getting branches for repo: %s/%s", project, slug)
        return [resources.BranchResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params)]

    def delete_branch(self, project, slug, branch_name):
        """Delete the given branch tag.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo.
            branch_name (str): The full ref for the branch to delete

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/branches'
        content = {'name': branch_name, 'dryRun': False}
        log.info("deleting branch: %s from %s/%s", branch_name, project, slug)
        return self.conn.delete(uri, json=content, base=self.api_versions.branch_utils)

    def repo_default_branch(self, project, slug):
        """Get the default branch for the given repo.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to change the default of.

        Returns:
            resources.BranchResource: default branch info

        Raises:
            HTTPError: if there is no default branch

        """
        uri = f'projects/{project}/repos/{slug}/branches/default'
        log.info("getting default branch for repo: %s/%s", project, slug)
        return resources.BranchResource(self.conn.get(uri), self, project, slug)

    def set_repo_default_branch(self, project, slug, branch_name):
        """ Set the given branch as the default branch.

        Args:
            project (str): The project key where the repo is located.
            slug (str): The repo to change the default of.
            branch_name (str): The default branch.

        Returns:
            True if successful

        Raises:
            HTTPError: if the change failed.
        """
        uri = f'projects/{project}/repos/{slug}/branches/default'
        log.info("setting default branch of repo %s/%s to %s", project, slug, branch_name)
        self.conn.put(uri, json={'id': branch_name}) # no content returned
        return True

    def repo_tags(self, project, slug, filter_text=None, break_point=None):
        """Get a list of tags for the given repo.

        Args:
            project: The project key where the repo is located.
            slug: The repo to get hook information.
            filter_text (optional str): the text to match on
            break_point (Optional [int]): approximate number of tags to retrieve

        Returns:
            list: list of resources.TagResource objects
        """
        uri = f'projects/{project}/repos/{slug}/tags'
        params = {}
        if filter_text:
            params['filterText'] = filter_text
        log.info("getting tags for repo: %s/%s", project, slug)
        return [resources.TagResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params, break_point=break_point)]

    def add_repo_tag(self, project, slug, tag_name, startpoint, message, force=False, lightweight=False):
        """Add a tag to the repo at location startpoint.

        Args:
            project: the project where the repo is located
            slug: the target repo
            tag_name: the tag name
            startpoint: a ref or commit for the tag
            message (str): message to accompany the tag
            force (optional bool): if the tag should be forced
            lightweight (optional bool): if the tag should be a lightweight tag or annotated.
                Default is false, giving an annotated tag.

        Returns:
            resources.TagResource object
        """
        uri = f'projects/{project}/repos/{slug}/tags'
        content = {
            'force': force,
            'name': tag_name,
            'startPoint': startpoint,
            'type': 'ANNOTATED',
            'message': message,
        }
        if lightweight:
            content['type'] = 'LIGHTWEIGHT'
        log.info("adding tag '%s' to repo '%s/%s' at %s", tag_name, project, slug, startpoint)
        # TODO should this be using the git endpoint or the default?
        return resources.TagResource(decode_json(self.conn.post(uri, json=content, base=self.api_versions.git)),
                                     self, project, slug)

    def delete_repo_tag(self, project, slug, tag):
        """Delete the given tag from the repo.

        Args:
            project: the project where the repo is located
            slug: the target repo
            tag (str): tag to delete

        Returns:
            None
        """
        log.info("deleting tag '%s' from repo '%s/%s'", tag, project, slug)
        uri = f'projects/{project}/repos/{slug}/tags/{tag}'
        self.conn.delete(uri, base=self.api_versions.git)

    def repo_hooks(self, project, slug):
        """Get a list of hook configurations for the given repo.

        Args:
            project: The project key where the repo is located.
            slug: The repo to get hook information.

        Returns:
            list: A list of resources.HookResource containing hook configuration.

        Raises:
            HTTPError: if the repo was not found.
        """
        log.info("getting hooks for repo: %s/%s", project, slug)
        uri = f'projects/{project}/repos/{slug}/settings/hooks'
        return [resources.HookResource(r, self, project, slug) for r in self.conn.get_paged(uri)]

    def enable_hook(self, project, slug, hook_key, settings=None):
        """Enable the given hook with the given settings.

        Args:
            project: The project key where the repo is located.
            slug: The repo where the hook will be enabled.
            hook_key: The long name of the hook.
                Ex: com.atlassian.stash.stash-bundled-hooks:force-push-hook
            settings: Optional dictionary for configuring the new hook.

        Returns:
            resources.HookResource

        Raises:
            HTTPError: if there was a problem enabling the hook.

        """
        log.info("enabling hook '%s' for repo %s/%s", hook_key, project, slug)
        uri = f'projects/{project}/repos/{slug}/settings/hooks/{hook_key}/enabled'
        return resources.HookResource(decode_json(self.conn.put(uri, json=settings)), self, project, slug)

    def disable_hook(self, project, slug, hook_key):
        """Disable the given hook in the given repo.

        Args:
            project: The project key where the repo is located.
            slug: The repo where the hook will be disabled.
            hook_key: The long name of the hook to be disabled.
                Ex: com.atlassian.stash.stash-bundled-hooks:force-push-hook

        Returns:
            resources.HookResource

        Raises:
            HTTPError: if there was a problem disabling the hook.
        """
        log.info("disabling hook '%s' for repo %s/%s", hook_key, project, slug)
        uri = f'projects/{project}/repos/{slug}/settings/hooks/{hook_key}/enabled'
        return resources.HookResource(decode_json(self.conn.delete(uri)), self, project, slug)

    def hook_settings(self, project, slug, hook_key):
        """Get the settings for the given hook.

        Args:
            project: The project key where the repo is located.
            slug: The repo who's hook settings to get.
            hook_key: The long name of the hook to get the settings of.
                Ex: com.atlassian.stash.stash-bundled-hooks:force-push-hook

        Returns:
            resources.HookResource: the hook settings.
        """
        log.info("getting settings for hook '%s' in repo %s/%s", hook_key, project, slug)
        uri = f'projects/{project}/repos/{slug}/settings/hooks/{hook_key}/settings'
        return resources.HookResource(self.conn.get(uri), self, project, slug)

    def update_hook_settings(self, project, slug, hook_key, settings):
        """Update the given hook's settings.

        Args:
            project: The project key where the repo is located.
            slug: The repo who's hook settings to change.
            hook_key: The long name of the hook to get the settings of.
                Ex: com.atlassian.stash.stash-bundled-hooks:force-push-hook
            settings: Dictionary containing settings information to change.

        Returns:
            resources.HookResource: the hook settings
        """
        log.info("updating settings for hook '%s' in repo %s/%s", hook_key, project, slug)
        uri = f'projects/{project}/repos/{slug}/settings/hooks/{hook_key}/settings'
        return resources.HookResource(decode_json(self.conn.put(uri, json=settings)), self, project, slug)

    def repo_shortcut_links(self, project, slug):
        """Get the shortcut links related to this repo.

        Args:
            project (str): The project key
            slug (str): The repo slug

        Returns:
            list: list of link dictionaries
        """
        log.info("getting shortcut links for '%s/%s'", project, slug)
        uri = f'projects/{project}/repos/{slug}/shortcuts'
        return self.conn.get_paged(uri, base=self.api_versions.shortcuts)

    def create_new_repo_shortcut_link(self, project, slug, url, label):
        """Create a new shortcut link in the sidebar for the repo.

        Args:
            project (str): The project key
            slug (str): The repo slug.
            url (str): The URL to link to.
            label (str): The Link's label.

        Returns:
            dict: the newly created label
        """
        log.info("creating new shortcut link for '%s/%s'", project, slug)
        uri = f'projects/{project}/repos/{slug}/shortcuts'
        content = {
            "url": url,
            "label": label
        }
        return self.conn.post(uri, base=self.api_versions.shortcuts, json=content)

    def update_repo_shortcut_link(self, project, slug, link_id, url, label):
        """Update a shortcut link. All arguments are required, even if they didn't change.

        Args:
            project (str): The project key
            slug (str): The repo slug.
            link_id (int): the link ID
            url (str): The URL to link to.
            label (str): The Link's label.

        Returns:
            dict: the updated link
        """
        log.info("updating shortcut link %s for '%s/%s'", link_id, project, slug)
        uri = f'projects/{project}/repos/{slug}/shortcuts/{link_id}'
        content = {
            "url": url,
            "label": label
        }
        return self.conn.put(uri, base=self.api_versions.shortcuts, json=content)

    def delete_repo_shortcut_link(self, project, slug, link_id):
        """Removes the given shortcut link.

        Args:
            project (str): The project key
            slug (str): The repo slug.
            link_id (int): the link ID
                Fetch the links for the repo first to obtain the ID.
        """
        log.info("deleting shortcut link %s for '%s/%s'", link_id, project, slug)
        uri = f'projects/{project}/repos/{slug}/shortcuts/{link_id}'
        self.conn.delete(uri, base=self.api_versions.shortcuts)

    def pull_request_settings(self, project, slug):
        """Get a dictionary of pull request settings.

        Added BBS v4.7.1

        Args:
            project: project key
            slug: repo slug

        Returns:
            dict: dictionary of pull request settings
        """
        log.info("getting pull request settings for %s/%s", project, slug)
        uri = f'projects/{project}/repos/{slug}/settings/pull-requests'
        return self.conn.get(uri)

    def set_pull_request_settings(self, project, slug,
                                  requiredApprovers=None,
                                  requiredAllTasksComplete=None,
                                  requiredSuccessfulBuilds=None):
        """Set pull request settings for the given repo.

        Args:
            project: project key
            slug: repo slug
            requiredApprovers (int):
                the number of approvals required on a pull request for it to be mergeable
            requiredAllTasksComplete (bool):
                whether or not all tasks on a pull request need to be completed for it to be mergeable
            requiredSuccessfulBuilds (int):
                the number of successful builds on a pull request for it to be mergeable

        Returns:
            dict: updated dictionary of pull request settings
        """
        uri = f'projects/{project}/repos/{slug}/settings/pull-requests'
        payload = {}
        # TODO: is there some way to *unset* any of these fields with the API?
        if requiredApprovers is not None:
            payload['requiredApprovers'] = requiredApprovers
        if requiredAllTasksComplete is not None:
            payload['requiredAllTasksComplete'] = requiredAllTasksComplete
        if requiredSuccessfulBuilds is not None:
            payload['requiredSuccessfulBuilds'] = requiredSuccessfulBuilds
        return decode_json(self.conn.post(uri, json=payload))

    def repo_branch_permissions(self, project, slug):
        """Get the current branch permissions for the given repo.

        Args:
            project: The project key where the repo is located.
            slug: The repo.

        Returns:
            list: List of resources.SettingsResource of branch permission settings.
        """
        log.info("getting branch permission settings for repo: %s/%s", project, slug)
        uri = f'projects/{project}/repos/{slug}/restrictions'
        return [resources.SettingsResource(r, self) for r in self.conn.get_paged(uri, base=self.api_versions.permissions)]

    def set_repo_branch_permissions_pattern(self, project, slug, pattern,
                                       write_access=None, pull_request=None, branch_delete=None, rewrite_history=None):
        """Set pattern branch permissions.

        All optional arguments are setup to expect a list or tuple of two elements:
            0 - [list of usernames]
            1 - [list of groups]
        If either should be empty, pass an empty list.

        Args:
            project: The project key where the repo is located.
            slug: The repo.
            pattern: The pattern to set.
            write_access: Users/groups that will have write access to the branch pattern.
            pull_request: Users/groups that can perform changes without a pull request.
            branch_delete: Users/groups that can delete branches that match the pattern.
            rewrite_history: Users/groups that can rewrite commit history.

        Returns:
            None
        """
        # read-only = Limit Write Access to
        # pull-request-only = Prevent changes without a pull request
        # no-deletes = Prevent branch deletion
        # fast-forward-only = Prevent rewriting history
        log.info("setting branch permission pattern '%s' in repo %s/%s", pattern, project, slug)
        if write_access is None:
            write_access = ([], [])
        if pull_request is None:
            pull_request = ([], [])
        if branch_delete is None:
            branch_delete = ([], [])
        if rewrite_history is None:
            rewrite_history = ([], [])
        self._set_branch_permissions_pattern(project, slug, pattern, 'read-only',
                                             write_access[0], write_access[1])
        self._set_branch_permissions_pattern(project, slug, pattern, 'pull-request-only',
                                             pull_request[0], pull_request[1])
        self._set_branch_permissions_pattern(project, slug, pattern, 'no-deletes',
                                             branch_delete[0], branch_delete[1])
        self._set_branch_permissions_pattern(project, slug, pattern, 'fast-forward-only',
                                             rewrite_history[0], rewrite_history[1])

    def _set_branch_permissions_pattern(self, project, slug, pattern, permission, allowed_users, allowed_groups):
        # this will just build and run an individual dictionary
        # replaces existing users and groups for the given pattern
        perm_group = {
            'type': permission, # read-only, pull-request-only, no-deletes, fast-forward-only
            'matcher': {
                'active': True,
                'displayId': pattern,
                'id': pattern,
                'type': {'id': 'PATTERN', 'name': 'Pattern'},
            },
            'users': allowed_users,
            'groups': allowed_groups,
        }
        uri = f'projects/{project}/repos/{slug}/restrictions'
        return self.conn.post(uri, json=perm_group, base=self.api_versions.permissions)

    def repo_branch_model(self, project, slug):
        """Get the branch model settings for the given repo.

        Args:
            project: The project where the repo is located.
            slug: The repo.

        Returns:
            dict: The branch model settings for the given repo.
        """
        log.info("getting branching model for repo: %s/%s", project, slug)
        uri = f'projects/{project}/repos/{slug}/branchmodel'
        return self.conn.get(uri, base=self.api_versions.branch_utils)

    def set_repo_branch_model(self, project, slug, branch_model):
        """Set repo branch model.

        Args:
            project ([type]): [description]
            slug ([type]): [description]
            branch_model (dict): the JSON representation of the updated branch model
        """
        # Undocumented API endpoint, described here:
        # https://jira.atlassian.com/browse/BSERV-5411?focusedCommentId=2385714&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-2385714
        log.info("getting branching model for repo: %s/%s", project, slug)
        uri = f'projects/{project}/repos/{slug}/branchmodel/configuration'
        return self.conn.post(uri, json=branch_model)

    def commit_build_statuses(self, commit):
        """Get a list of commit build statuses using old the endpoint.

        Args:
            commit (str): full SHA1 of the commit

        Returns:
            list: list of resources.BuildStatusResources for the builds
        """
        log.info("getting build status for commit: %s", commit)
        uri = f'commits/{commit}'
        return [resources.BuildStatusResource(r, self) for r in self.conn.get_paged(uri, base=self.api_versions.build_status)]

    def post_build_status(self, commit, state, key, url, name=None, description=None):
        """Associate a build status with a commit using the old endpoint.

        Args:
            commit (str): full SHA1 of the commit
            state (str): state of the build: SUCCESSFUL, FAILED or INPROGRESS.
            key (str): key for the build plan
            url (str): URL to the build
            name (optional str): name of the build
            description (optional str): description of the build

        Returns:
            none
        """
        uri = f'commits/{commit}'
        content = {
            'state': state,
            'key': key,
            'url': url,
        }
        if name is not None:
            content['name'] = name
        if description is not None:
            content['description'] = description
        log.info("posting build status of '%s' to commit %s", state, commit)
        self.conn.post(uri, json=content, base=self.api_versions.build_status)
        # returns no content

    def post_build_status_new(self, project, slug, commit, build_json):
        """Post a build status using the new endpoint.

        Example:

            {
                "key": "TEST-REP123",
                "state": "SUCCESSFUL",
                "url": "https://bamboo.url/browse/TEST-REP1-3",
                "buildNumber": "3",
                "description": "Unit test build",
                "duration": 1500000,
                "lastUpdated": 1359075920,
                "name": "Database Matrix Tests",
                "parent": "TEST-REP",
                "ref": "refs/heads/master",
                "testResults": {
                    "failed": 1,
                    "skipped": 8,
                    "successful": 0
                }
            }

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit (str): full SHA1 of the commit
            build_json (dict): build info dictionary
        """
        uri = f'projects/{project}/repos/{slug}/commits/{commit}/builds'
        self.conn.post(uri, json=build_json)
        # returns no content

    def commit_build_status(self, project, slug, commit, key):
        """Get a specific build status.

        Args:
            project ([type]): [description]
            slug ([type]): [description]
            commit ([type]): [description]
            key ([type]): [description]

        Returns:
            resources.BuildStatusResource
        """
        uri = f'projects/{project}/repos/{slug}/commits/{commit}/builds'
        params = {
            'key': key
        }
        return resources.BuildStatusResource(self.conn.get(uri, parameters=params))

    def delete_commit_build_status(self, project, slug, commit, key):
        """Delete the specified build result.
        Note: this only works for build statuses created with the newer
        endpoint. BB always returns 204 regardless of if it deleted anything.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit (str): full SHA1 of the commit
            key (str): the key for the build
        """
        uri = f'projects/{project}/repos/{slug}/commits/{commit}/builds'
        params = {
            'key': key
        }
        self.conn.delete(uri, parameters=params)
        # returns no content

    def commit_build_statistics(self, commit, includeunique=False):
        """Gets statistics regarding the builds associated with a commit.

        Args:
            commit (str): full SHA1 of the commit
            includeunique (optional bool): include unique build info
                If there is only one of any given type of build, include its info.
        Returns:
            dict
        """
        uri = f'commits/stats/{commit}'
        params = {}
        if includeunique:
            params['includeUnique'] = True
        stats = self.conn.get(uri, parameters=params, base=self.api_versions.build_status)
        results = []
        if 'results' in stats: # we need to convert to BuildStatusResources...
            for r in stats['results']:
                results.append(resources.BuildStatusResource(r))
        stats['results'] = results
        log.info("getting build statistics for commit: %s", commit)
        return stats

    def issue_commits(self, issue_key):
        """Get commits that are associated with the given issue key.

        Args:
            issue_key (str): the JIRA issue key

        Returns:
            list: list of related commits
        """
        uri = f'issues/{issue_key}/commits'
        return self.conn.get_paged(uri, base=self.api_versions.jira)

    def create_pull_request(self, title, from_ref, to_ref,
                            from_proj=None, from_repo=None,
                            to_proj=None, to_repo=None,
                            reviewers=None, description=None):
        """Create a pull request.

        At least one pair of project, slug must be specified.

        Args:
            title (str): the title of the pull request
            from_ref (str): the `from` git reference
            to_ref (str): the `to` git reference
            from_proj (optional str): the `from` project
            from_repo (optional str): the `from` repo
            to_proj (optional str): the `to` project
            to_repo (optional str): the `to` repo
            reviewers (optional list): optional list of usernames as strings
            description (optional str): optional description for the pull request

        Returns:
            resources.PullRequestResource
        """
        def either_or(a, b):
            if a is None: a = b
            if b is None: b = a
            return a, b
        if reviewers is None:
            reviewers = []
        # Fill out any missing arguments
        from_proj, to_proj = either_or(from_proj, to_proj)
        from_repo, to_repo = either_or(from_repo, to_repo)
        if not all([from_repo, to_repo, from_proj, to_proj]):
            raise ValueError("must specify a repository and a project")
        uri = f'projects/{to_proj}/repos/{to_repo}/pull-requests' # Is always in the to_repo regardless
        content = {
            'title': title,
            'fromRef': {
                'id': from_ref,
                'repository': {
                    'slug': from_repo,
                    'project': {'key': from_proj}
                }
            },
            'toRef': {
                'id': to_ref,
                'repository': {
                    'slug': to_repo,
                    'project': {'key': to_proj}
                }
            },
            'reviewers': [],
        }
        if description:
            content['description'] = description
        for reviewer in reviewers:
            content['reviewers'].append({'user': {'name': str(reviewer)}})
        return resources.PullRequestResource(decode_json(self.conn.post(uri, json=content)), self, to_proj, to_repo)

    def pull_requests(self, project, slug, all=False, branch=None, outgoing=False, reverse=False, state=None, break_point=None):
        """Get the pull requests for a repository.

        By default, this API call returns open PRs only. Use the optional arguments
        to modify what is returned.

        Args:
            project (str): the project key
            slug (str): the repo slug
            all (bool): get all pull requests if True
                Overrides the state argument if provided.
            branch (str): limit pull requests to the given fully-qualified branch
            outgoing (bool): get outgoing pull requests instead of incoming
            reverse (bool): order oldest to newest instead of the default
            state (str): get all pull requests that are of the given state.
                OPEN, DECLINED, MERGED or ALL
            break_point (Optional [int]): approximate number of pull requests to retrieve

        Returns:
            list of PullRequestResource objects
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests'
        params = {}
        if branch:
            params['at'] = branch
        if outgoing: # API default is incoming
            params['direction'] = 'outgoing'
        if state:
            params['state'] = state
        if all:
            params['state'] = 'all'
        if reverse: # default is 'newest'
            params['order'] = 'oldest'
        return [resources.PullRequestResource(r, self, project, slug) for r in self.conn.get_paged(uri, parameters=params, break_point=break_point)]

    def pull_request(self, project, slug, request_id):
        """Get a specific pull request for a repository.

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull request number

        Returns:
            resources.PullRequestResource
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}'
        return resources.PullRequestResource(self.conn.get(uri), self, project, slug)

    def update_pull_request_info(self, project, slug, request_id, title=None, description=None):
        """Update the review

        Args:
            project:
            slug:
            request_id:
            title:
            description:

        Returns:

        """
        # this uri/call could also be used to add/update/change reviewers, but seems cumbersome
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}'
        content = {
            'id': request_id,
        }
        if title:
            content['title'] = title
        if description:
            content['description'] = description
        return resources.PullRequestResource(self.conn.put(uri, json=content), self, project, slug)

    def add_user_to_pull_request(self, project, slug, request_id, username, role='REVIEWER'):
        """Add a user to the specified pull request

        Args:
            project:
            slug:
            request_id:
            username:
            role (optional): role to add the user as. Default is 'REVIEWER'

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/participants'
        content = {
            'user': {'name': username},
            'role': role,
        }
        resources.ParticipantResource(self.conn.post(uri, json=content), self)

    def pull_request_participants(self, project, slug, request_id):
        """

        Args:
            project:
            slug:
            request_id:

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/participants'
        return [resources.ParticipantResource(r, self) for r in self.conn.get_paged(uri)]

    def update_pull_request_participant(self, project, slug, request_id, username, role=None, status=None):
        """Update a participant's status.

        Args:
            project:
            slug:
            request_id:
            username:

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/participants/{username}'
        content= {} # TODO: this might require 'user': {...},
        if role:
            content['role'] = role
        if status:
            content['status'] = status
        self.conn.put(uri, json=content)

    def remove_user_from_pull_request(self, project, slug, request_id, username):
        """Remove a reviewer from a pull request and make them just a participant.

        Args:
            project:
            slug:
            request_id:
            username:

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/participants/{username}'
        self.conn.delete(uri)

    def approve_pull_request(self, project, slug, request_id, username=None):
        """Approve a pull request with the given user.

        Args:
            project:
            slug:
            request_id:
            username:

        Returns:

        """
        # TODO: is this the correct way to do this?
        # TODO: perhaps just use the logged in user here
        if not username:
            username = self._username
        self.update_pull_request_participant(project, slug, request_id, username, status='APPROVED')

    def decline_pull_request(self, project, slug, request_id, version):
        """Decline a pull request with the logged in user.

        Args:
            project: the given project
            slug: the repo slug
            request_id (int): the ID# of the pull request to decline
            version (int): the version number of the pull request to decline

        Returns:
            PullRequestResource
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/decline'
        params = {
            'version': str(version), # Yes, for some reason it requires it to be a string
        }
        return resources.PullRequestResource(decode_json(self.conn.post(uri, parameters=params)), self, project, slug)

    def merge_pull_request(self, project, slug, request_id, version):
        """Merge an approved pull request to its destination.

        Args:
            project: the project key
            slug: the repo slug
            request_id (int): the pull request ID#
            version (int): the version ID of the pull request to merge

        Returns:
            PullRequestResource
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/merge'
        params = {
            'version': str(version)
        }
        return resources.PullRequestResource(decode_json(self.conn.post(uri, parameters=params)), self, project, slug)

    def pull_request_merge_status(self, project, slug, request_id):
        """Return a status dictionary of a pull request.

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull request number

        Returns:
            dict: the merge statuses, or None if merged
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/merge'
        try:
            return self.conn.get(uri)
        except BitbucketServerException as bbse:
            # Merged PRs raise 409: Conflict when they are already merged.
            if bbse.response.status_code != 409:
                raise
            # return None in the case of already merged

    def reopen_pull_request(self, project, slug, request_id, version):
        """

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull request number
            version (int): the version number to reopen

        Returns:
            PullRequestResource
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/reopen'
        params = {
            'version': str(version)
        }
        return resources.PullRequestResource(decode_json(self.conn.post(uri, parameters=params)), self, project, slug)

    def pull_request_activities(self, project, slug, request_id, from_id=None, from_type=None):
        """Retrieve all activity associated with a pull request.

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull reuqest ID#
            from_id (optional int): the id of the activity item to use as the first item in the list
            from_type (optional str): the type of the activity item specified by from_id
                Required if from_id is specified. Either COMMENT or ACTIVITY.

        Returns:
            list: PullRequestActivityResource
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/activities'
        params = {}
        if from_id:
            params['fromId'] = from_id
        if from_type:
            params['fromType'] = from_type
        return [resources.PullRequestActivityResource(r, self, project, slug, request_id) for r in self.conn.get_paged(uri, params)]

    def pull_request_changes(self, project, slug, request_id):
        """

        Args:
            project:
            slug:
            request_id:

        Returns:
            list: ChangesResources
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/changes'
        return [resources.ChangesResource(r, self, project, slug) for r in self.conn.get_paged(uri)]

    def pull_request_commits(self, project, slug, request_id):
        """

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull reuqest ID#

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/commits'
        return [resources.CommitResource(r, self, project, slug) for r in self.conn.get_paged(uri)]

    def pull_request_comments(self, project, slug, request_id, path, anchor_state='ALL'):
        """Get the comments on the given pull request.
        WARNING: this can't return root comments, only on-file comments.

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull request ID#
            path (str): path and filename that exists in the PR.
            anchor_state (str): the state of the comment to retrieve.
                (ACTIVE, ORPHANED, or ALL) Default: ALL

        Returns:
            list: list of comments
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/comments'
        params = {
            'anchorState': anchor_state,
            'path': path,
        }
        return self.conn.get_paged(uri, parameters=params)

    def add_pull_request_comment(self, project, slug, request_id, text,
        task=False, parent_comment=None,
        path=None, line=None):
        """Add a comment to a given pull request with an optional filepath.

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull request ID#
            text (str): comment message text
            task (bool, optional): if the comment should be a Task. Defaults to False.
            parent_comment (int, optional): A parent comment to reply to.
            path (str): path and filename that exists in the PR.
            line (int, optional): line number to anchor the comment to.
                Leaving blank will be a full file comment.

        Returns:
            resources.PullRequestCommentResource
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/comments'
        params = None
        body = {
            'text': text,
            'severity': 'NORMAL',
        }
        if task is True:
            body['severity'] = 'BLOCKER'
        if parent_comment is not None:
            body['parent'] = {
                "id": int(parent_comment)
            }
        elif path is not None:
            body['anchor'] = {
                'path': path
            }
            if line is not None:
                body['anchor']['line'] = int(line)
                body['anchor']['lineType'] = 'ADDED'
        return resources.PullRequestCommentResource(
            decode_json(self.conn.post(uri, parameters=params, json=body)),
            self,
            project=project,
            slug=slug,
            pr_id=request_id
        )

    def pull_request_diffs(self, project, slug, request_id, path=None,
            context_lines=None, diff_type=None, since_id=None, until_id=None,
            src_path=None, ignore_whitespace=False, with_comments=None):
        """Get the diff from within a pull request.

        Note: this endpoint is currently not paged.
        The server will internally apply a hard cap to the streamed lines,
        and it is not possible to request subsequent pages if that cap is exceeded.

        Args:
            project (str): the project key
            slug (str): the repo slug
            request_id (int): the pull request ID#
            path (str, optional): The path within the repo to diff.
                Leave empty to pull all changes.
            context_lines (int, optional): Number of lines of context for the diff.
            diff_type (str, optional): the type of diff to request.
            since_id (str, optional): since commit hash to fetch diff from
            until_id (str, optional): until commit hash to fetch diff to
            src_path (str, optional): the previous path for the file,
                if it has been moved or copied.
            ignore_whitespace (bool, optional): whitespace flag. Defaults to False.
                If specified, will send the value of 'ignore-all' to ignore whitespace.
            with_comments (bool, optional): flag to include comments or not.
                When left blank, uses Bitbucket's default of include=True.

        Returns:
            dict: diff dictionary of the results.
        """
        uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/diff'
        if path is not None:
            uri = f"{uri}/{path}"
        params = {}
        if context_lines is not None:
            params['contextLines'] = context_lines
        if diff_type is not None:
            params['diffType'] = diff_type
        if since_id is not None:
            params['sinceId'] = since_id
        if until_id is not None:
            params['untilId'] = until_id
        if src_path is not None:
            params['srcPath'] = src_path
        if ignore_whitespace:
            params['whitespace'] = 'ignore-all'
        if with_comments is not None:
            params['contextLines'] = with_comments
        return self.conn.get(uri, parameters=params)

    def pull_request_tasks(self, project, slug, request_id):
        """Get the tasks associated with a pull request.

        Args:
            project:
            slug:
            request_id:

        Returns:
            list: TaskResources
        """
        if self._server_version > (7, 2):
            uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/blocker-comments'
            res = resources.PullRequestCommentResource
        else:
            uri = f'projects/{project}/repos/{slug}/pull-requests/{request_id}/tasks'
            res = resources.TaskResource
        return [res(r, self, project, slug, request_id) for r in self.conn.get_paged(uri)]

    def task(self, task_id):
        """Get a task by ID.

        Args:
            task_id (int): the task ID

        Returns:
            TaskResource
        """
        if self._server_version >= (8, 0, 0):
            raise DeprecationWarning("this endpoint is deprecated in 8.0, use 'pull_request_comment'")
        uri = f'tasks/{task_id}'
        return resources.TaskResource(self.conn.get(uri))

    def resolve_task(self, task_id):
        """Resolve the given task.

        Args:
            task_id (int): the task ID to resolve

        Returns:
            TaskResource: the updated task
        """
        if self._server_version >= (8, 0, 0):
            raise DeprecationWarning("this endpoint is deprecated in 8.0, use 'update_pull_request_comment'")
        uri = f'tasks/{task_id}'
        return resources.TaskResource(decode_json(self.conn.put(uri, json={'state': 'RESOLVED'})), self)

    def open_task(self, task_id):
        """(Re)open the given task.

        Args:
            task_id (int): the task ID to reopen

        Returns:
            TaskResource: the updated task
        """
        if self._server_version >= (8, 0, 0):
            raise DeprecationWarning("this endpoint is deprecated in 8.0, use 'update_pull_request_comment'")
        uri = f'tasks/{task_id}'
        return resources.TaskResource(decode_json(self.conn.put(uri, json={'state': 'OPEN'})), self)

    def delete_task(self, task_id):
        """Delete the given task.

        Args:
            task_id (int): the task ID to reopen

        Returns:
            None
        """
        if self._server_version >= (8, 0, 0):
            raise DeprecationWarning("this endpoint is deprecated in 8.0, use 'delete_pull_request_comment'")
        uri = f'tasks/{task_id}'
        self.conn.delete(uri)

    def update_task(self, task_id, text=None, state=None):
        """Update the given task ID.

        Note: changing the text reopens the task if it is closed.

        Args:
            task_id (int): the task ID
            text (optional string): the task's text to update
            state (optional string): the state of the task

        Returns:
            TaskResource: the updated task
        """
        if self._server_version >= (8, 0, 0):
            raise DeprecationWarning("this endpoint is deprecated in 8.0, use 'update_pull_request_comment'")
        uri = f'tasks/{task_id}'
        data = {}
        if text:
            data['text'] = text
        if state:
            data['state'] = state
        return resources.TaskResource(decode_json(self.conn.put(uri, json=data)), self)

    def user_ssh_keys(self, username=None):
        """Get a list of public SSH Keys for the given user.

        Args:
            username (optional str): username to get ssh keys for
                Defaults to currently logged in user

        Returns:

        """
        uri = 'keys'
        params = {}
        if username:
            params['user'] = username
        return [resources.SSHKeyResource(k) for k in self.conn.get_paged(uri, parameters=params, base=self.api_versions.ssh)]

    def add_user_ssh_key(self, ssh_key, username=None):
        """Add the given SSH key to the given user

        Args:
            ssh_key (str): SSH-RSA key to add
            username (optional str): username to add the SSH key to
                if no username is supplied, the current user is used

        Returns:
            SSHKeyResource
        """
        params = {}
        if username:
            params['user'] = username
        contents = {
            'text': ssh_key
        }
        log.info('adding SSH key for user %s', username)
        return resources.SSHKeyResource(decode_json(self.conn.post('keys', parameters=params, json=contents, base=self.api_versions.ssh)))

    def project_ssh_keys(self, project, filter=None, permission=None):
        """Retrieves the access keys for the given project.

        Args:
            project:
            filter: filter on the label, prefix match *only*
            permission: filter on the keys' permissions

        Returns:
            list of SSH keys
        """
        uri = f'projects/{project}'
        params = {}
        if filter is not None:
            params['filter'] = filter
        if permission is not None:
            params['permission'] = permission
        return [resources.SSHKeyResource(k) for k in self.conn.get_paged(uri, parameters=params, base=self.api_versions.keys)]

    def repo_ssh_keys(self, project, slug, filter=None, permission=None):
        """Retrieves the access keys for the given repository.

        Args:
            project:
            slug:
            filter: filter on the label, prefix match *only*
            permission: filter on the keys' permissions

        Returns:
            list: SSHKeyResources
        """
        uri = f'projects/{project}/repos/{slug}/ssh'
        params = {}
        if filter is not None:
            params['filter'] = filter
        if permission is not None:
            params['permission'] = permission
        return [resources.SSHKeyResource(k) for k in self.conn.get_paged(uri, parameters=params, base=self.api_versions.keys)]

    def add_repo_ssh_key(self, project, slug, public_key, permission_level):
        """Add an access key to the given repo with the given permission level.

        Args:
            project (str): the project key
            slug (str): the repo slug
            public_key (str): the public key file to load, or the public key string itself
            permission_level (str): the permission level for the given key

        Returns:

        """
        uri = f'projects/{project}/repos/{slug}/ssh'
        # If we were given a file, open it and read it
        if exists(public_key):
            with open(public_key) as fp:
                key = fp.read()
        else: # assume we were given the key
            key = public_key
        contents = {
            'key': {'text': key},
            'permission': permission_level
        }
        return self.conn.post(uri, json=contents, base=self.api_versions.keys)

    def user_access_tokens(self, username):
        """Get the given user's access tokens.

        Args:
            username (str): the username

        Returns:
            list: list of UserAccessTokens
        """
        uri = f'users/{username}'
        return [resources.UserAccessToken(t, self) for t in self.conn.get_paged(uri, base=self.api_versions.access_tokens)]

    def user_access_token(self, username, token_id):
        """Get the given access token.

        Args:
            username (str): the username
            token_id (str): the token ID

        Returns:
            UserAccessTokens
        """
        uri = f'users/{username}/{token_id}'
        return resources.UserAccessToken(self.conn.get(uri, base=self.api_versions.access_tokens), self)

    def create_user_access_token(self, username, token_name, permissions):
        """Create a new user access token for the given user.

        Args:
            username: the username to create it for
            token_name: the name of the token
            permissions (list): the permissions to grant the token
                A list of permission strings.

        Returns:
            UserAccessToken
        """
        uri = f'users/{username}'
        content = {
            'name': token_name,
            'permissions': permissions
        }
        return resources.UserAccessToken(decode_json(self.conn.put(uri, json=content, base=self.api_versions.access_tokens)), self)

    def update_user_access_token(self, username, token_id, token_name=None, permissions=None):
        """Update the given token.

        Args:
            username: the username of the token
            token_id: the token's internal ID
            token_name (optional): update the token name
            permissions (optional): update the token's permissions

        Returns:
            UserAccessToken
        """
        uri = f'users/{username}/{token_id}'
        content = {}
        if token_name is not None:
            content['name'] = token_name
        if permissions is not None:
            content['permissions'] = permissions
        return resources.UserAccessToken(decode_json(self.conn.post(uri, json=content, base=self.api_versions.access_tokens)), self)

    def delete_user_access_token(self, username, token_id):
        """Revokes the given access token.

        Args:
            username (str): the token's owner
            token_id (str): the token's ID

        Returns:
            None
        """
        uri = f'users/{username}/{token_id}'
        self.conn.delete(uri, base=self.api_versions.access_tokens)

    def labels(self):
        """Get the list of repo labels defined in the system.
        These are *not* git tags.

        Returns:
            list: list of labels
        """
        # {'name': 'labelname'}
        # should this be an object that just acts like a string?
        return [l['name'] for l in self.conn.get_paged("labels")]

    def label(self, label_name):
        """Get the given label from the server.
        *NOT* git tag/labels.

        Args:
            label_name (str): the label name
        """
        uri = f"labels/{label_name}"
        return self.conn.get(uri)

    def labeled_items(self, label_name, label_type=None):
        """Get a list of labeled objects.

        Args:
            label_name (str): the label name
            label_type (str, optional): The object type to filter on.
                Currently only REPOSITORY is supported.

        Returns:
            list: list of dictionaries of returned objects
        """
        uri = f"labels/{label_name}/labeled"
        params = {}
        if label_type:
            params['type'] = label_type
        return self.conn.get_paged(uri, parameters=params)

    def repo_labels(self, project, slug):
        """Get the labels for the given repo. These are NOT git tags.

        Args:
            project (str): the project key
            slug (str): the repo slug

        Returns:
            list: list of labels for the repo
        """
        uri = f"projects/{project}/repos/{slug}/labels"
        return [l['name'] for l in self.conn.get_paged(uri)]

    def add_repo_label(self, project, slug, label_name):
        """Label a repository. These are NOT git tags.

        Args:
            project (str): the project key
            slug (str): the repo slug
            label_name (str): the label name
        """
        uri = f"projects/{project}/repos/{slug}/labels"
        content = {
            "name": label_name
        }
        return self.conn.post(uri, json=content).json()

    def delete_repo_label(self, project, slug, label_name):
        """Remove a label from a repository. These are NOT git tags.

        Args:
            project (str): the project key
            slug (str): the repo slug
            label_name (str): the label name
        """
        uri = f"projects/{project}/repos/{slug}/labels/{label_name}"
        self.conn.delete(uri)

    def repo_webhooks(self, project, slug):
        """Get all webhooks for the given repo.

        Args:
            project (str): the project key
            slug (str): the repo slug

        Returns:
            list: list of WebhookResources
        """
        uri = f"projects/{project}/repos/{slug}/webhooks"
        return [resources.WebhookResource(r, self, project=project, slug=slug) for r in self.conn.get_paged(uri)]

    def repo_webhook(self, project, slug, hook_id):
        """Get a specific webhook with the given ID.

        Args:
            project (str): the project key
            slug (str): the repo slug
            hook_id (int): the hook ID

        Returns:
            WebhookResource
        """
        uri = f"projects/{project}/repos/{slug}/webhooks/{hook_id}"
        return resources.WebhookResource(self.conn.get(uri), self, project=project, slug=slug)

    def webhook_latest_event(self, project, slug, hook_id):
        """Get the most recent invocation of the given webhook.

        Args:
            project (str): the project key
            slug (str): the repo slug
            hook_id (int): the hook ID
        """
        uri = f"projects/{project}/repos/{slug}/webhooks/{hook_id}/latest"
        return self.conn.get(uri)

    def webhook_statistics(self, project, slug, hook_id):
        """Get a specific webhook with the given ID.

        Args:
            project (str): the project key
            slug (str): the repo slug
            hook_id (int): the hook ID
        """
        uri = f"projects/{project}/repos/{slug}/webhooks/{hook_id}/statistics"
        return self.conn.get(uri)

    def webhook_statistics_summary(self, project, slug, hook_id):
        """Get a specific webhook with the given ID.

        Args:
            project (str): the project key
            slug (str): the repo slug
            hook_id (int): the hook ID
        """
        uri = f"projects/{project}/repos/{slug}/webhooks/{hook_id}/statistics/summary"
        return self.conn.get(uri)

    def code_insight_reports(self, project, slug, commit_hash):
        """Get all code insight reports for the given commit.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash

        Returns:
            list: list of CodeInsightReport objects
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports"
        reports = self.conn.get_paged(uri, base=self.api_versions.insights)
        return [resources.CodeInsightReport(r, self, project, slug, commit_hash) for r in reports]

    def code_insight_report(self, project, slug, commit_hash, report_key):
        """Get the given insight report for this commit.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): the unique key for the report

        Returns:
            CodeInsightReport: the report
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports/{report_key}"
        return resources.CodeInsightReport(
            self.conn.get(uri, base=self.api_versions.insights),
            self, project, slug, commit_hash
        )

    def create_code_insight_report(self, project, slug, commit_hash, report_key, insight_json):
        """Create a new Insight Report object. This must be done prior to adding annotations.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): the unique key for the report
                Should be a name associated with the source of the report,
                e.g. the tool name or report type.
            insight_json (dict): the contents of the report
                Must cotain the following values:
                    title (str): the title of the insight report
                Optional:
                    details (str): description of the report
                    result (str): PASS or FAIL if appropriate
                    data (list): List of data fields with user facing info
                        about the report
                    reporter (str): string to describe the tool that generated
                        the report
                    link (str): URL to the results of the report
                    logoUrl (str): link to the logo to use

        For information on what fields are required, and other related info,
        see the REST resource documentation for code insights:
            https://docs.atlassian.com/bitbucket-server/rest/6.0.0/bitbucket-code-insights-rest.html

        Example insight_json:

            {
                "data": [
                    {
                        "title": "Some title",
                        "value": "Some value",
                        "type": "TEXT"
                    },
                    {
                        "title": "Build length",
                        "value": 60000,
                        "type": "DURATION"
                    },
                    {
                        "title": "Download link",
                        "value": "http://example.com/path/to/download",
                        "type": "LINK"
                    },
                    {
                        "title": "Some bool",
                        "value": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "title": "Build started date",
                        "value": 1539656375,
                        "type": "DATE"
                    },
                    {
                        "title": "Code coverage",
                        "value": 85,
                        "type": "PERCENTAGE"
                    },
                    {
                        "title": "Some count",
                        "value": 5,
                        "type": "NUMBER"
                    }
                ],
                "details": "This is the details of the report,
                    it can be a longer string describing the report",
                "title": "report.title",
                "reporter": "Reporter/tool that produced this report",
                "createdDate": 1549862571301,
                "link": "http://insight.host.com",
                "logoUrl": "http://insight.host.com/logo",
                "result": "PASS"
            }

        Returns:
            CodeInsightReport
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports/{report_key}"
        ci = decode_json(self.conn.put(uri, base=self.api_versions.insights, json=insight_json))
        return resources.CodeInsightReport(ci, self, project, slug, commit_hash)

    def delete_code_insight_report(self, project, slug, commit_hash, report_key):
        """Deletes the given isnight report.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): the unique key for the report
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports/{report_key}"
        self.conn.delete(uri, base=self.api_versions.insights)

    def add_code_insight_report_annotations(self, project, slug, commit_hash, report_key, annotations, external_id=None):
        """Add annotations to the given report_key report.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): the unique key for the report
            annotations (list): list of annotation dictionaries
            external_id (str): optional external ID to differentiate these within the report key

        Example annotations:

            {
                "annotations": [
                    {
                        "externalId": "message-1",
                        "line": 4,
                        "link": "https://link.to.tool/that/produced/annotation/message-1",
                        "message": "This is a bug here because reasons",
                        "path": "path/to/file/in/repo",
                        "severity": "MEDIUM",
                        "type": "CODE_SMELL"
                    },
                    {
                        "line": 2,
                        "message": "This is a vulnerability, but I don't need to access it again so I haven't given it an external ID",
                        "path": "path/to/another/file/in/repo",
                        "severity": "HIGH"
                    },
                    {
                        "externalId": "file-annotation-1",
                        "line": 0,
                        "link": "https://link.to.tool/that/produced/annotation/file-annotation-1",
                        "message": "This whole file needs to be annotated",
                        "path": "path/to/file/in/repo",
                        "severity": "LOW",
                        "type": "VULNERABILITY"
                    }
                ]
            }

        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports/{report_key}/annotations"
        if external_id is not None:
            uri += f"/{external_id}"
        content = {
            "annotations": annotations
        }
        self.conn.post(uri, json=content, base=self.api_versions.insights)

    def code_insight_report_annotations(self, project, slug, commit_hash, report_key):
        """Get the annotations associated with a report.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): the unique key for the report

        Returns:
            list: list of annotation dictionaries
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports/{report_key}/annotations"
        return self.conn.get(uri, base=self.api_versions.insights).get("annotations", [])

    def delete_code_insight_report_annotations(self, project, slug, commit_hash, report_key, external_id=None):
        """Delete the annotations in a given report.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): the unique key for the report
            external_id (str): the unique external ID for the individual annotation to remove.
                If not provided, all annotations are deleted.
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/reports/{report_key}/annotations"
        params = {}
        if external_id is not None:
            params['externalId'] = external_id
        self.conn.delete(uri, parameters=params, base=self.api_versions.insights)

    def commit_code_insight_annotations(self, project, slug, commit_hash,
            report_key=None, external_id=None, path=None, severity=None, type=None):
        """Get the code insight annotations for a given commit.

        Args:
            project (str): the project key
            slug (str): the repo slug
            commit_hash (str): the 40-character git commit hash
            report_key (str): optionally filter by report key
            external_id (str): optionally filter by external id
            path (str): optionally filter by path
                Partial paths/wildcards do *not* work.
            severity (str): optionally filter by severity
                One of: LOW, MEDIUM, HIGH
            type (str): optional filter by type
                One of: VULNERABILITY, CODE_SMELL, BUG

        Returns:
            list: list of annotations
        """
        uri = f"projects/{project}/repos/{slug}/commits/{commit_hash}/annotations"
        params = {}
        if report_key is not None:
            params['key'] = report_key
        if external_id is not None:
            params['externalId'] = external_id
        if path is not None:
            params['path'] = path
        if severity is not None:
            params['severity'] = severity
        if type is not None:
            params['type'] = type
        return self.conn.get(uri, parameters=params, base=self.api_versions.insights).get('annotations', [])
