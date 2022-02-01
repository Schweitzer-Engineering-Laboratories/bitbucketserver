"""
Copyright (C) 2021 Schweitzer Engineering Laboratories, Pullman, Washington

Resources

Container objects for the Bitbucket Server REST API.
Objects here should not be directly instantiated by the user;
they should be created by the functions of the BitbucketServer object.
"""
# pylint: disable=E1101
from datetime import datetime
import json
import logging
log = logging.getLogger(__name__)


def translate_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp / 1000.0)


class BitbucketAttribute(dict):
    """Container class for holding child attributes."""

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)

    def __dir__(self):
        return list(self.keys())


class BitbucketObject(object):
    """Base Bitbucket Server resource object."""

    _raw = None
    _server = None

    def __init__(self, resource_dict, server=None):
        """Create a Bitbucket resource.

        Args:
            resource_dict (BitbucketAttribute): base object dictionary
            server (bitbucketserver.BitbucketServer): the server object that created this object
        """
        self._raw = resource_dict
        self._server = server

    def _update(self, other):
        if not self.__class__ == other.__class__:
            raise RuntimeError("failed to update object: type mismatch ({0} != {1})".format(
                self.__class__, other.__class__))
        self._raw = other._raw
        self._server = other._server

    @property
    def server(self):
        if self._server is None:
            raise Exception("No server connection object present in object")
        return self._server

    def __getattr__(self, item):
        try:
            return self._raw[item]
        except KeyError:
            return object.__getattribute__(self, item)

    def __getitem__(self, item):
        return self._raw[item]

    def __iter__(self):
        raise TypeError("'{}' object is not iterable".format(self.__class__.__name__))

    def __eq__(self, other):
        hash_eq = False
        raw_eq = False
        is_eq = self is other
        if isinstance(other, self.__class__):
            try:
                hash_eq = hash(self) == hash(other)
            except TypeError:
                hash_eq = False
            if hasattr(other, '_raw'):
                raw_eq = self._raw == other._raw
        return any([raw_eq, hash_eq, is_eq])

    def __contains__(self, item):
        return hasattr(self, item)

    def __dir__(self):
        return list(self._raw.keys()) + list(dir(type(self)))


class ProjectContextBitbucketObject(BitbucketObject):
    """A BitbucketObject that is relative to a specific project"""

    def __init__(self, resource_dict, server=None, project=None):
        super(ProjectContextBitbucketObject, self).__init__(resource_dict, server)
        self._parent_project_key = project
        self._project_obj = None

    def _update(self, other):
        super(ProjectContextBitbucketObject, self)._update(other)
        self._parent_project_key = other._parent_project_key

    @property
    def project(self):
        if self._project_obj is None:
            self._project_obj = self.server.project(self._parent_project_key)
        return self._project_obj


class RepoContextBitbucketObject(ProjectContextBitbucketObject):
    """A child BitbucketObject that is relative to a specific repo."""

    def __init__(self, resource_dict, server=None, project=None, slug=None):
        super(RepoContextBitbucketObject, self).__init__(resource_dict, server, project)
        self._parent_slug = slug
        self._repo = None

    def _update(self, other):
        super(RepoContextBitbucketObject, self)._update(other)
        self._parent_slug = other._parent_slug

    @property
    def repo(self):
        if self._repo is None:
            self._repo = self.server.repo(self._parent_project_key, self._parent_slug)
        return self._repo

    @property
    def compound_key(self):
        """The compound key of project key, repo slug.

        Returns:
            tuple: the project key, repo slug
        """
        return self._parent_project_key, self._parent_slug

class BaseRefResourceObject(RepoContextBitbucketObject):

    def __init__(self, resource_dict, server=None, project=None, slug=None):
        super(BaseRefResourceObject, self).__init__(resource_dict, server, project, slug)
        self._commit = None

    def __repr__(self):
        return '<%s(id=%s)>' % (self.__class__.__name__, self.id)

    def __str__(self):
        return str(self.id)

    def __hash__(self):
        return hash(self.id)

    def files(self, path=None):
        """Returns a list of strings for the files at this ref.

        Args:
            path (str): directory path to get file list.
                Will return all files if left blank.

        Returns:
            list: list of strings of repo relative paths and filenames.
        """
        return self.server.repo_files(self._parent_project_key, self._parent_slug, path=path, at=self.id)

    def file_contents(self, filepath):
        """Returns the contents of a file at this ref.

        Args:
            filepath: full repo-relative path to the file.

        Returns:
            list: list of strings for the file contents
        """
        return self.server.file_contents(self._parent_project_key, self._parent_slug, filepath=filepath, at=self.id)

    def raw_file(self, path):
        """Get the given file's contents at this commit.
        WARNING: heavy use of this may cause performance issues for the server.

        Args:
            path (str): the file path to get.

        Returns:
            bytes: the raw file contents
        """
        return self.server.raw_file(self._parent_project_key, self._parent_slug, path, at=self.id)

    @property
    def commit(self):
        """The commit associated with this

        Returns:
            CommitResource: the commit currently linked to this ref
        """
        if self._commit is None:
            self._commit = self.server.repo_commit(self._parent_project_key, self._parent_slug, self.latestCommit)
        return self._commit

    @property
    def name(self):
        return self.displayId


class BranchResource(BaseRefResourceObject):
    """Bitbucket Server branch resource."""

    def create_outgoing_pull_request(self, title, to_ref, to_repo=None, to_proj=None, description=None,
                                     reviewers=None):
        """Create a pull request outgoing from this branch.

        Args:
            title (str): the title of the pull request
            to_ref (str): target ref to merge to.
            to_repo (optional str): a different repo slug to merge to
            to_proj (optional str): a different project key for the other repo
            description (optional str): the description for the pull request
            reviewers (optional list): list of usernames as strings
        Returns:
            PullRequestResource
        """
        return self.server.create_pull_request(
            title=title,
            from_proj=self._parent_project_key,
            from_repo=self._parent_slug,
            from_ref=self.id,
            to_ref=to_ref,
            to_repo=to_repo,
            to_proj=to_proj,
            description=description,
            reviewers=reviewers
            )

    def create_incoming_pull_request(self, title, from_ref, from_repo=None, from_proj=None, description=None,
                                     reviewers=None):
        """Create a pull request incoming to this branch.

        Args:
            title (str): the title of the pull request
            from_ref (str): target ref to merge from.
            from_repo (optional str): a different repo slug to merge from
                Assumed to be the repo of this branch object if not given
            from_proj (optional str): a different project key for the other repo
                Assumed to be the project of this branch's repo if not given
            description (optional str): the description for the pull request
            reviewers (optional list): list of usernames as strings
        Returns:
            PullRequestResource
        """
        return self.server.create_pull_request(
            title=title,
            from_proj=from_proj,
            from_repo=from_repo,
            from_ref=from_ref,
            to_ref=self.id,
            to_repo=self._parent_slug,
            to_proj=self._parent_project_key,
            description=description,
            reviewers=reviewers
            )

    def commits(self, break_point=None):
        """Get a list of commits on this branch.

        Args:
            break_point (int): approximate number of records to retrieve

        Returns:
            list: list of commits on this branch
        """
        return self.server.repo_commits(self._parent_project_key, self._parent_slug,
                                            until=self.id, break_point=break_point)

    def delete(self):
        """Delete this branch."""
        return self.server.delete_branch(self._parent_project_key, self._parent_slug, self.id)

    def set_as_default_branch(self):
        self.server.set_repo_default_branch(self._parent_project_key, self._parent_slug, self.displayId)

    # TODO: PR fetching related things


class BuildStatisticResource(BitbucketObject):
    """Bitbucket Server build statistics resource."""
    pass


class BuildStatusResource(BitbucketObject):
    """Bitbucket Server build status resource."""

    def __repr__(self):
        return '<%s(key=%s, state=%s)>' % (self.__class__.__name__, self.key, self.state)

    @property
    def passed(self):
        return self.state == 'SUCCESSFUL'

    @property
    def failed(self):
        return self.state == 'FAILED'

    @property
    def in_progress(self):
        return self.state == 'INPROGRESS'


class ChangesResource(RepoContextBitbucketObject):
    """Bitbucket Server Changes resource."""

    def __repr__(self):
        return '<%s(path=%s)>' % (self.__class__.__name__, self.path.toString)


class CommitResource(BaseRefResourceObject):
    """Bitbucket Server commit resource."""

    def __init__(self, *args, **kwargs):
        super(CommitResource, self).__init__(*args, **kwargs)

    def __repr__(self):
        return '<%s(id=%s)>' % (self.__class__.__name__, self.id)

    def _update(self, other):
        super(CommitResource, self)._update(other)

    @property
    def authorTimestamp(self):
        return translate_timestamp(self._raw['authorTimestamp'])

    def branches(self):
        """Get the branches associated with this changeset.

        Returns:
            list: list of resources.BranchResources associated with the given commit
        """
        return self.server.commit_branches(self._parent_project_key, self._parent_slug, self.id)

    def build_statuses(self):
        """Get build statues for this commit.

        Returns:
            list: list of resources.BuildStatusResources for the builds
        """
        return self.server.commit_build_statuses(self.id)

    def add_build(self, state, key, url, name=None, description=None):
        """Add a build status to this commit.

        Args:
            state (str): state of the build: SUCCESSFUL, FAILED or INPROGRESS.
            key (str): key for the build plan
            url (str): URL to the build
            name (optional str): name of the build
            description (optional str): description of the build

        Returns:
            None
        """
        self.server.post_build_status(self.id, state, key, url, name=name, description=description)

    def build_statistics(self, includeunique=False):
        """Get build statistics for this commit.

        Args:
            includeunique (optional bool): include unique build info
                If there is only one of any given type of build, include its info.

        Returns:
            BuildStatisticResource
        """
        return self.server.commit_build_statistics(self.id, includeunique=includeunique)

    def changes(self):
        """Get a list of changes in this commit since its parent(s).

        Returns:
            list: list of ChangesResource objects
        """
        if len(self.parents) >= 2: # merge commit
            changes = []
            for parent in self.parents:
                changes += self.changes_since(parent.id)
        else: # normal commit
            changes = self.server.repo_commit_changes(self._parent_project_key, self._parent_slug, self.id)
        return changes

    def changes_since(self, commit_hash):
        """Get the changes in a commit since the given commit.

        Args:
            commit_hash (str): commit hash to get changes since.

        Returns:
            list: list of ChangesResource objects
        """
        return self.server.repo_commit_changes(self._parent_project_key, self._parent_slug, self.id, since=commit_hash)

    def code_insight_reports(self):
        return self.server.code_insight_reports(
            self._parent_project_key,
            self._parent_slug,
            self.id
        )

    def code_insight_report(self, report_key):
        return self.server.code_insight_report(
            self._parent_project_key,
            self._parent_slug,
            self.id,
            report_key
        )

    def create_code_insight_report(self, report_key, insight_json):
        return self.server.create_code_insight_report(
            self._parent_project_key,
            self._parent_slug,
            self.id,
            report_key,
            insight_json,
        )

    def code_insight_annotations(self, report_key=None, external_id=None, path=None, severity=None, type=None):
        return self.server.commit_code_insight_annotations(
            self._parent_project_key,
            self._parent_slug,
            self.id,
            report_key=report_key,
            external_id=external_id,
            path=path,
            severity=severity,
            type=type,
        )

    def add_tag(self, name, message, force=False, lightweight=False):
        """Add a tag to the given commit.

        Args:
            name (str): the tag name
            message (str): message to accompany the tag creation
            force (optional bool): if the tag should be forced
            lightweight (optional bool): if the tag should be a lightweight tag or annotated.
                Default is false, giving an annotated tag.

        Returns:
            TagResource: The created tag.
        """
        return self.server.add_repo_tag(self._parent_project_key, self._parent_slug, tag_name=name,
                                        startpoint=self.id, message=message, force=force,
                                        lightweight=lightweight)

    def tags(self):
        """Get the tags for this commit.

        Returns:
            list: list of TagResources
        """
        tags = [] # TODO: is this the best we can do?
        for tag in self.server.repo_tags(self._parent_project_key, self._parent_slug):
            if tag.latestChangeset == self.id:
                tags.append(tag)
        return tags

    @property
    def commit(self): # because with the parent class, this is meaningless.
        return self

    def pull_requests(self):
        """Get the pull requests for this commit.

        Returns:
            list: list of PullRequestResources
        """
        return self.server.commit_pull_requests(self._parent_project_key, self._parent_slug, self.id)

class FileDiffResource(RepoContextBitbucketObject):
    """Bitbucket Server File Diff Resource."""

    def __iter__(self):
        for hunk in self.hunks:
            yield hunk


class HookResource(RepoContextBitbucketObject):
    """Bitbucket Server hook resource."""

    @property
    def key(self):
        return self.details.key

    @property
    def name(self):
        return self.details.name

    def enable(self, settings=None):
        """Enable this hook with the given settings.

        Args:
            settings (optional dict): dictionary for configuring the new hook

        Returns:
            None
        """
        self._update(self.server.enable_hook(self._parent_project_key, self._parent_slug, self.key, settings=settings))

    def disable(self):
        """Disable this hook.

        Returns:
            None
        """
        self._update(self.server.disable_hook(self._parent_project_key, self._parent_slug, self.key))

    def update(self, settings=None):
        """Update this hook with the given settings.

        Args:
            settings (optional dict): dictionary for configuring the new hook

        Returns:
            None
        """
        self._update(self.server.update_hook_settings(self._parent_project_key, self._parent_slug, self.key, settings=settings))

    def __str__(self):
        return self.key


class ParticipantResource(BitbucketObject):
    """Bitbucket Server review participant resource."""

    @property
    def is_author(self):
        return self.role == 'AUTHOR'

    @property
    def is_reviewer(self):
        return self.role == 'REVIEWER'

    def __repr__(self):
        return '<%s(participant=%s)>' % (self.__class__.__name__, self.user.name)


class ProjectAuditResource(ProjectContextBitbucketObject):
    """Bitbucket Server Audit resource object"""

    def detail_dictionary(self):
        """Parse the detail string and convert to a dictionary.

        Returns:
            dict: parsed event details

        Exceptions:
            ValueError: if JSON parsing failed.
        """
        try:
            return json.loads(self._raw['details'])
        except KeyError:
            return {}


class ProjectResource(BitbucketObject):
    """Bitbucket Server project resource."""

    def __repr__(self):
        return '<%s(key=%s)>' % (self.__class__.__name__, self.key)

    @property
    def url(self):
        """Return the web URL for this resource."""
        try:
            return self.links.self[0].href
        except:
            return None

    def audit(self, break_point=None):
        """Retrieves the audit events for this project.

        Args:
            break_point (int): approximate number of records to retrieve

        Returns:
            list: list: the projects' audit
        """
        return self.server.project_audit(self.key, break_point=break_point)

    def repos(self):
        """Get a list of repositories in this project.

        Returns:
            list: list of RepositoryResources for this project.
        """
        return self.server.repos(self.key)

    def repo(self, slug):
        """Get the given repo from this project.

        Args:
            slug (str): the repo slug
        """
        return self.server.repo(self.key, slug)

    def create_repo(self, repo_name, forkable=True, public=False):
        """Create a new repo in the given project.

        Args:
            repo_name (str): The plain English name of the new repo.
                Bitbucket will auto-create the repo slug.
            forkable (Optional [bool]): Flag for if the repo is forkable or not.
                Defaults to True.
            public (Optional [bool]): Flag for if the repo is publically available.
                Defaults to False.

        Returns:
            resources.RepositoryResource

        Raises:
            HTTPError: if the repo could not be created.
        """
        return self.server.create_repo(self.key, repo_name, forkable=forkable, public=public)

    def search_repos(self, repo_name=None, break_point=None):
        """Search for repos in this project.

        Args:
            repo_name (str): optional search string.
            break_point (int): approximate number of records to retrieve

        Returns:
            list: list of repositories

        """
        return self.server.search_repos(repo_name=repo_name, project_name=self.name, break_point=break_point)

    def delete_repo(self, slug):
        """Delete the given repo.

        Args:
            slug (str): the repo slug
        """
        return self.server.delete_repo(self.key, slug)

    def delete(self):
        """Deletes this project.

        Returns:
            None
        """
        self.server.delete_project(self.key)

    def group_permissions(self, filter=None):
        """Get the group permissions for this project.

        Args:
            filter (str): group name to filter by

        Returns:
            list: the list of group permissions for the project
        """
        return self.server.project_group_permissions(self.key, filter=filter)

    def group_no_permissions(self, filter=None):
        """Get a list of groups that have no permissions for this project.

        Args:
            filter (str): group name to filter by

        Returns:
            list: list of groups
        """
        return self.server.project_group_no_permissions(self.key, filter=filter)

    def set_group_permission(self, group, permission):
        """Add or set group permissions for this project.

        Args:
            group (str): the group name
            permission (str): the permission to add

        Returns:
            None
        """
        return self.server.set_project_group_permission(self.key, group, permission)

    def delete_group_permission(self, group):
        """Delete the given group's permissions from the project.

        Args:
            project (str): the project key
            group (str): the group name

        Returns:
            None
        """
        return self.server.delete_project_group_permission(self.key, group)

    def user_permissions(self, filter=None):
        """Get the user permissions for this project.

        Args:
            filter (str): user name to filter by

        Returns:
            list: the list of user permissions for the project
        """
        return self.server.project_user_permissions(self.key, filter=filter)

    def user_no_permissions(self, filter=None):
        """Get a list of users that have no permissions for this project.

        Args:
            filter (str): user name to filter by

        Returns:
            list: list of users
        """
        return self.server.project_user_no_permissions(self.key, filter=filter)

    def set_user_permission(self, user, permission):
        """Add or set user permissions for this project.

        Args:
            user (str): the user name
            permission (str): the permission to add

        Returns:
            None
        """
        return self.server.set_project_user_permission(self.key, user, permission)

    def delete_user_permission(self, user):
        """Delete the given user's permissions from the project.

        Args:
            project (str): the project key
            user (str): the user name

        Returns:
            None
        """
        return self.server.delete_project_user_permission(self.key, user)

    def get_default_permission(self, project_permission):
        """Get the given default permission

        Args:
            project_permission (str): the project permission

        Returns:
            bool: if the given permission is allowed or not
        """
        return self.server.project_default_permission(self.key, project_permission)

    def set_default_permission(self, project_permission, allow):
        """Set the default permission for the given permission level.

        Args:
            project_permission (str): the permission level
            allow (bool): true to grant, false to revoke
        """
        self.server.set_project_default_permission(self.key, project_permission, allow)

    def __str__(self):
        return self.key


class PullRequestResource(RepoContextBitbucketObject):
    """Bitbucket Pull Request resource."""

    def __init__(self, resource_dict, server=None, project=None, slug=None):
        super(PullRequestResource, self).__init__(resource_dict, server, project, slug)
        # Make the reviewers a resource instead of attribute:
        self.reviewers = [ParticipantResource(r, self.server) for r in self._raw['reviewers']]

    @property
    def url(self):
        """Return the web URL for this resource."""
        try:
            return self.links.self[0].href
        except:
            return None

    def __repr__(self):
        return '<%s(project=%s, repo=%s, id=%i)>' % (self.__class__.__name__, self._parent_project_key, self._parent_slug, self.id)

    def _update(self, other):
        super(PullRequestResource, self)._update(other)
        self.reviewers = [ParticipantResource(r, self.server) for r in self._raw['reviewers']]

    @property
    def compound_key(self):
        """The compound key of project key, repo slug, id

        Returns:
            tuple: the project key, repo slug, pr id
        """
        return self._parent_project_key, self._parent_slug, self.id

    @property
    def participants(self):
        # use participants as a property to override the empty list given by the normal pullrequest getters
        return self.server.pull_request_participants(self._parent_project_key, self._parent_slug, self.id)

    @property
    def declined(self):
        return self.state == 'DECLINED'

    @property
    def merged(self):
        return self.state == 'MERGED'

    @property
    def createdDate(self):
        return translate_timestamp(self._raw['createdDate'])

    @property
    def closedDate(self):
        return translate_timestamp(self._raw['closedDate'])

    @property
    def updatedDate(self):
        return translate_timestamp(self._raw['updatedDate'])

    def tasks(self):
        return self.server.pull_request_tasks(self._parent_project_key, self._parent_slug, self.id)

    def approve(self):
        self.server.approve_pull_request(self._parent_project_key, self._parent_slug, self.id, self.version)

    def decline(self):
        self._update(self.server.decline_pull_request(self._parent_project_key, self._parent_slug, self.id, self.version))

    def merge(self):
        self._update(self.server.merge_pull_request(self._parent_project_key, self._parent_slug, self.id, self.version))

    @property
    def can_merge(self):
        stat = self.merge_status()
        return stat['canMerge']

    def merge_status(self):
        return self.server.pull_request_merge_status(self._parent_project_key, self._parent_slug, self.id)

    def reopen(self):
        self._update(self.server.reopen_pull_request(self._parent_project_key, self._parent_slug, self.id, self.version))

    def activities(self, from_id=None, from_type=None):
        return self.server.pull_request_activities(self._parent_project_key, self._parent_slug, self.id, from_id, from_type)

    def changes(self):
        return self.server.pull_request_changes(self._parent_project_key, self._parent_slug, self.id)

    def commits(self):
        return self.server.pull_request_commits(self._parent_project_key, self._parent_slug, self.id)

    # TODO: pull request diffs


class PullRequestContextBitbucketObject(RepoContextBitbucketObject):
    """A child BitbucketObject that is relative to a specific repo."""

    def __init__(self, resource_dict, server=None, project=None, slug=None, pr_id=None):
        super(PullRequestContextBitbucketObject, self).__init__(resource_dict, server, project, slug)
        self._pull_request_id = pr_id

    def _update(self, other):
        super(PullRequestContextBitbucketObject, self)._update(other)
        self._pull_request_id = other._pull_request_id


class PullRequestActivityResource(PullRequestContextBitbucketObject):
    """Activity on a pull request"""

    def __repr__(self):
        return '<%s(project=%s, repo=%s, pr_id=%s, action=%s, id=%s)>' % (
            self.__class__.__name__,
            self._parent_project_key,
            self._parent_slug,
            self._pull_request_id,
            self.action,
            self.id,
        )


class RepositoryAuditResource(RepoContextBitbucketObject):
    """Bitbucket Server Audit resource object"""

    def detail_dictionary(self):
        """Parse the detail string and convert to a dictionary.

        Returns:
            dict: parsed event details

        Exceptions:
            ValueError: if JSON parsing failed.
        """
        try:
            return json.loads(self._raw['details'])
        except KeyError:
            return {}


class RepositoryResource(BitbucketObject):
    """Bitbucket Server repository resource."""

    _ssh_url = None

    def __repr__(self):
        return '<%s(project=%s, slug=%s)>' % (self.__class__.__name__, self.project.key, self.slug)

    def __int__(self):
        return int(self.id)

    @property
    def compound_key(self):
        """The compound key of project key, repo slug.

        Returns:
            tuple: the project key, repo slug
        """
        return self.project.key, self.slug

    def _update(self, other):
        super(RepositoryResource, self)._update(other)
        self._ssh_url = None

    @property
    def ssh_url(self):
        if self._ssh_url is None:
            for link in self.links.clone:
                if link.name == 'ssh':
                    self._ssh_url = link.href
                    break
        return self._ssh_url


    @property
    def url(self):
        """Return the web URL for this resource."""
        try:
            return self.links.self[0].href
        except:
            return None

    def audit(self):
        """Get a list of audit events for this repo.

        Returns:
            list: the audit events for this repository.
        """
        return self.server.repo_audit(self.project.key, self.slug)

    def create_outgoing_pull_request(self, title, from_ref, to_ref, to_repo=None, to_proj=None, description=None,
                                     reviewers=None):
        """Create a pull request outgoing from this repo.

        Args:
            title (str): the title of the pull request
            from_ref(str): the ref to merge from
            to_ref (str): target ref to merge to
            to_repo (optional str): a different repo slug to merge to
            to_proj (optional str): a different project key for the other repo
            description (optional str): the description for the pull request
            reviewers (optional list): list of usernames as strings
        Returns:
            PullRequestResource
        """
        return self.server.create_pull_request(
            from_proj=self.project.key,
            from_repo=self.slug,
            title=title,
            from_ref=from_ref,
            to_ref=to_ref,
            to_repo=to_repo,
            to_proj=to_proj,
            description=description,
            reviewers=reviewers
            )

    def create_incoming_pull_request(self, title, from_ref, to_ref, from_repo=None, from_proj=None, description=None,
                                     reviewers=None):
        """Create a pull request incoming to this repo.

        Args:
            title (str): the title of the pull request
            from_ref (str): target ref to merge from
            to_ref (str): target ref to merge to
            from_repo (optional str): a different repo slug to merge from
                Assumed to be the repo of this branch object if not given
            from_proj (optional str): a different project key for the other repo
                Assumed to be the project of this branch's repo if not given
            description (optional str): the description for the pull request
            reviewers (optional list): list of usernames as strings
        Returns:
            PullRequestResource
        """
        return self.server.create_pull_request(
            from_proj=from_proj,
            from_repo=from_repo,
            title=title,
            from_ref=from_ref,
            to_ref=to_ref,
            to_repo=self.slug,
            to_proj=self.project.key,
            description=description,
            reviewers=reviewers
            )

    def commit(self, commit_hash, path=None):
        """Get a specific commit.

        Args:
            commit_hash: full SHA1 of the changeset
            path (optional str): optional path to filter commits by.
                If not for the specified commit, this option will then return the
                first instance where path matches.

        Returns:
            resources.CommitResource
        """
        return self.server.repo_commit(self.project.key, self.slug, commit_hash=commit_hash, path=path)

    def commits(self, path=None, since=None, until=None, break_point=None):
        """Get a list of commits from the repo.

        Args:
            path (Optional[str]): An optional path to filter commits by.
            since (Optional[str]): The commit hash or ref to retrieve commits after (exclusive).
            until (Optional[str]): The commit hash or ref to retrieve commits before (inclusive).
            break_point (int): approximate number of records to retrieve

        Returns:
            list: List of resources.CommitResource for the given repo.
        """
        return self.server.repo_commits(self.project.key, self.slug, path=path, since=since, until=until, break_point=break_point)

    def compare_changes(self, from_ref=None, to_ref=None, from_repo=None):
        return self.server.compare_changes(self.project.key, self.slug, from_ref=from_ref,
                                           to_ref=to_ref, from_repo=from_repo)

    def forks(self):
        """Get a list of this repo's forks.

        Returns:
            list: list of RepositoryResource objects
        """
        return self.server.repo_forks(self.project.key, self.slug)

    def fork_repo(self, fork_name, destination_project=None):
        """Fork this repo.

        Args:
            fork_name (str): The plain English name of the forked repo.
            destination_project (Optional [str]): The destination project to put the fork.
                Defaults to None, which places the fork in the current user's personal repos.

        Returns:
            resources.RepositoryResource: the forked repo

        Raises:
            HTTPError: if the fork failed.
        """
        return self.server.fork_repo(self.project.key, self.slug, fork_name=fork_name,
                                     destination_project=destination_project)

    def related_repos(self):
        """Get a list of repos related to this repo.

        Returns:
            list: List of resources.RepositoryResource that are directly related (via forking, etc)
                to the given repo.
        """
        return self.server.related_repos(self.project.key, self.slug)

    def create_branch(self, branch_name, start_ref, message=None):
        """Create a new branch tag.

        Args:
            branch_name (str): The name of the new branch.
            start_ref (str): The ref where the branch tag should go.
            message (Optional [str]): The optional commit message for creating the branch.

        Returns:
            resources.BranchResource: the new branch.

        Raises:
            HTTPError: if the branch creation failed.
        """
        return self.server.create_branch(self.project.key, self.slug, branch_name=branch_name, start_ref=start_ref,
                                         message=message)

    def branches(self, filterText=None, base=None, details=False, alphabetical=False, break_point=None):
        """Get a list of branches associated with the given repo.

        Args:
            filterText (Optional [str]): Text to match on.
            base (Optional [str]): base branch or tag to compare each branch to. Defaults to None.
            details (Optional [bool]): whether to retrieve plugin-provided metadata about each branch.
                Defaults to False.
            alphabetical (Optional [bool]): List branches alphabetically instead of in order.
            break_point (int): approximate number of records to retrieve

        Returns:
            list: List of resources.BranchResource containing branch information.
        """
        return self.server.repo_branches(self.project.key, self.slug, base=base, details=details,
                                         filterText=filterText, alphabetical=alphabetical,
                                         break_point=break_point)

    def delete_branch(self, branch_name):
        """Delete the given branch from this repo.

        Args:
            branch_name (str): the full ref for the branc to delete

        Returns:
            None
        """
        self.server.delete_branch(self.project.key, self.slug, branch_name)

    def default_branch(self):
        """Get the default branch for this repo.

        Returns:
            resources.BranchResource: default branch info
        """
        return self.server.repo_default_branch(self.project.key, self.slug)

    def set_default_branch(self, branch_name):
        """Set the default branch.

        Args:
            branch_name: the branch name

        Returns:
            True if successful
        """
        return self.server.set_repo_default_branch(self.project.key, self.slug, branch_name=branch_name)

    def files(self, path=None, at=None):
        """Returns a list of strings for the files in the repo.

        Args:
            path (str): directory path to get file list.
            at (str): hash or ref ID for where to get the file list

        Returns:
            list: list of strings of repo relative paths and filenames.
        """
        return self.server.repo_files(self.project.key, self.slug, path=path, at=at)

    def file_contents(self, filepath, at=None):
        """Returns the contents of a file at this branch as a list.

        Args:
            filepath: full repo-relative path to the file.
            at: hash or ref ID for where to get the file contents.

        Returns:
            list: list of strings for the file contents
        """
        return self.server.file_contents(self.project.key, self.slug, filepath=filepath, at=at)

    def raw_file(self, path, at=None):
        """Get the given file's contents.

        Args:
            path (str): the file path to get.
            at (str, optional): Defaults to None. The ref or hash to get the file at.

        Returns:
            byte: the contents of the file
        """
        return self.server.raw_file(self.project.key, self.slug, path, at)

    def tags(self, break_point=None):
        """Get a list of tags for this repo.

        Args:
            break_point (int): approximate number of records to retrieve

        Returns:
            list: list of resources.TagResource objects
        """
        return self.server.repo_tags(self.project.key, self.slug, break_point=break_point)

    def add_tag(self, name, startpoint, message, force=False, lightweight=False):
        """Add a tag to the repo at the location startpoint.

        Args:
            name: the tag name
            startpoint: a ref or commit for the tag
            message (str): message to accompany the tag
            force (optional bool): if the tag should be forced
            lightweight (optional bool): if the tag should be a lightweight tag or annotated.
                Default is false, giving an annotated tag.

        Returns:
            TagResource
        """
        return self.server.add_repo_tag(self.project.key, self.slug, tag_name=name, startpoint=startpoint, message=message,
                                        force=force, lightweight=lightweight)

    def delete_tag(self, tag):
        """Delete the given tag from the repo.

        Args:
            tag (str): tag name to delete

        Returns:
            None
        """
        return self.server.delete_repo_tag(self.project.key, self.slug, tag=tag)

    def hooks(self):
        """Get a list of hook configurations for this repo.

        Returns:
            list: A list of resources.HookResource containing hook configuration.
        """
        return self.server.repo_hooks(self.project.key, self.slug)

    def update(self, new_name=None, description=None, forkable=None, public=None):
        """Update this repo.

        Args:
            new_name (optional str): the new name for the repo
            description (Optional [str]): update the repository description.
            forkable (optional bool): the forkable flag
            public (optional bool): the public flag

        Returns:
            None
        """
        self._update(self.server.update_repo(self.project.key, self.slug,
            description=description, new_name=new_name, forkable=forkable,
            public=public))

    def move(self, new_project, new_name=None):
        """Move this repo to a new project.

        Args:
            new_project: project to move the repo to
            new_name (optional str): optionally rename the repo

        Returns:
            None
        """
        self._update(self.server.move_repo(self.project.key, self.slug, new_project=new_project, new_name=new_name))

    def delete(self):
        """Deletes this repo on the server.

        Returns:
            bool: True if successfully deleted
        """
        return self.server.delete_repo(self.project.key, self.slug)

    def pull_request(self, request_id):
        """Get a specific pull request for this repository.

        Args:
            request_id (int): the pull request number

        Returns:
            resources.PullRequestResource
        """
        return self.server.pull_request(self.project.key, self.slug, request_id)

    def pull_requests(self, all=False, branch=None, outgoing=False, reverse=False, state=None):
        return self.server.pull_requests(
            self.project.key, self.slug, all=all, branch=branch,
            outgoing=outgoing, reverse=reverse, state=state)

    def pull_request_settings(self):
        return self.server.pull_request_settings(self.project.key, self.slug)

    def set_pull_request_settings(self, requiredApprovers=None,
            requiredAllTasksComplete=None, requiredSuccessfulBuilds=None):
        return self.server.set_pull_request_settings(
            self.project.key,
            self.slug,
            requiredApprovers=requiredApprovers,
            requiredSuccessfulBuilds=requiredSuccessfulBuilds,
            requiredAllTasksComplete=requiredAllTasksComplete,
        )

    def add_access_key(self, public_key, permission_level):
        """

        Args:
            public_key (str): the public key file to load, or the public key string itself
            permission_level (str): the permission level for the given key

        Returns:

        """
        return self.server.add_repo_ssh_key(self.project.key, self.slug, public_key, permission_level)

    def group_permissions(self, filter=None):
        return self.server.repo_group_permissions(self.project.key, self.slug, filter)

    def group_no_permissions(self, filter=None):
        return self.server.repo_group_no_permissions(self.project.key, self.slug, filter)

    def set_group_permission(self, group, permission):
        return self.server.set_repo_group_permission(self.project.key, self.slug, group, permission)

    def delete_group_permission(self, group):
        return self.server.delete_repo_group_permission(self.project.key, self.slug, group)

    def user_permissions(self, filter=None):
        return self.server.repo_user_permissions(self.project.key, self.slug, filter)

    def user_no_permissions(self, filter=None):
        return self.server.repo_user_no_permissions(self.project.key, self.slug, filter)

    def set_user_permission(self, user, permission):
        return self.server.set_repo_user_permission(self.project.key, self.slug, user, permission)

    def delete_user_permission(self, user):
        return self.server.delete_repo_user_permission(self.project.key, self.slug, user)

    def webhooks(self):
        return self.server.repo_webhooks(self.project.key, self.slug)

    def webhook(self, hook_id):
        return self.server.repo_webhook(self.project.key, self.slug, hook_id)

    @property
    def lfs_enabled(self):
        return self.server.repo_git_lfs_status(self.project.key, self.slug)

    def enable_git_lfs(self):
        """Enable git lfs for this repo."""
        self.server.enable_git_lfs_in_repo(self.project.key, self.slug)

    def disable_git_lfs(self):
        """Disable git lfs for this repo."""
        self.server.disable_git_lfs_in_repo(self.project.key, self.slug)

    def __str__(self):
        return self.slug


class SettingsResource(BitbucketObject):
    """Bitbucket Server settings resource."""
    pass


class SSHKeyResource(BitbucketObject):
    """Bitbucket Server SSH key resource."""

    def __repr__(self):
        return '<%s(label=%s)>' % (self.__class__.__name__, self.label)


class TagResource(BaseRefResourceObject):
    """Bitbucket Server tag resource."""

    # TODO: maybe add a .move(self, ref)?

    def delete(self):
        self.server.delete_repo_tag(self._parent_project_key, self._parent_slug, self.id)


class TaskResource(BitbucketObject):
    """A pull request Task resource."""

    def resolve(self):
        self._update(self.server.resolve_task(self.id))

    def delete(self):
        self.server.delete_task(self.id)

    def open(self):
        self._update(self.server.open_task(self.id))

    def update(self, text=None, state=None):
        self._update(self.server.update_task(self.id, text, state))


class UserResource(BitbucketObject):
    """Bitbucket Server user resource."""

    def __repr__(self):
        return '<%s(slug=%s)>' % (self.__class__.__name__, self.slug)

    @property
    def project_key(self):
        return "~{0}".format(self.slug).upper()

    def repos(self):
        """Get the list of this user's personal repositories.

        Returns:
            list: list of RepositoryResources
        """
        return self.server.repos(self.project_key)

    def ssh_keys(self):
        return self.server.user_ssh_keys(self.slug)

    def add_ssh_key(self, ssh_key):
        return self.server.add_user_ssh_key(ssh_key, self.slug)

    def access_tokens(self):
        return self.server.user_access_tokens(self.slug)

    def __str__(self):
        return self.slug


class UserAccessToken(BitbucketObject):

    def __repr__(self):
        return '<%s(id=%s, name=%s)>' % (self.__class__.__name__, self.id, self.name)

    @property
    def token(self):
        if 'token' in self._raw:
            return self._raw['token']
        else:
            raise ValueError("a token's value is not available unless it is a newly created token")

    def update(self, token_name=None, permissions=None):
        self._server.update_user_access_token(self.user.slug, self.id, token_name=token_name, permissions=permissions)

    def delete(self):
        self._server.delete_user_access_token(self.user.slug, self.id)


class CodeInsightReport(RepoContextBitbucketObject):

    def __repr__(self):
        return '<%s(key=%s, title=%s)>' % (self.__class__.__name__, self.key, self.title)

    def __init__(self, resource_dict, server=None, project=None, slug=None, commit_hash=None):
        super(CodeInsightReport, self).__init__(resource_dict, server, project, slug)
        self._commit_hash = commit_hash
        self._annotations = None
        self._data = {}
        if 'data' in resource_dict:
            self._data = {x['title']: x['value'] for x in resource_dict['data']}

    def __str__(self):
        return self.key

    @property
    def report_key(self):
        return self.key

    @property
    def annotations(self):
        if self._annotations is None:
            self._annotations = self.server.code_insight_report_annotations(
                project_key=self._parent_project_key,
                slug=self._parent_slug,
                commit_hash=self._commit_hash,
                report_key=self.key,
            )
        return self._annotations

    @property
    def data(self):
        return self._data

    def add_annotations(self, annotations):
        """Add annotations to this report.

        Args:
            annotations (list): list of annocation dictionaries
        """
        self.server.add_code_insight_report_annotations(
            project=self._parent_project_key,
            slug=self._parent_slug,
            commit_hash=self._commit_hash,
            report_key=self.key,
            annotations=annotations,
        )

    def delete_annotations(self):
        """Deletes the annotations against this report."""
        self.server.delete_code_insight_report_annotations(
            project=self._parent_project_key,
            slug=self._parent_slug,
            commit_hash=self._commit_hash,
            report_key=self.key,
        )

    def delete(self):
        """Deletes this report object."""
        self.server.delete_code_insight_report(
            project=self._parent_project_key,
            slug=self._parent_slug,
            commit_hash=self._commit_hash,
            report_key=self.key,
        )

    def __iter__(self):
        for annotation in self.annotations:
            yield annotation


class WebhookResource(RepoContextBitbucketObject):

    def __repr__(self):
        return '<%s(project=%s, repo=%s, id=%i)>' % (self.__class__.__name__, self._parent_project_key, self._parent_slug, self.id)

    def latest_event(self):
        return self.server.webhook_latest_event(self._parent_project_key, self._parent_slug, self.id)

    def statistics(self):
        return self.server.webhook_statistics(self._parent_project_key, self._parent_slug, self.id)

    def statistics_summary(self):
        return self.server.webhook_statistics_summary(self._parent_project_key, self._parent_slug, self.id)
