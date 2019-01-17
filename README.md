# GitHub provider for SSSD

This fork of sssd contains an sssd id provider backed by GitHub accounts.
It queries the GitHub API to on-demand discover available users and
groups and make them available for authentication through SSSD. It
additionally collects SSH public keys for any mapped user, thus
allowing users to login with any key added to github if OpenSSH is
set up to accept SSH keys from SSSD (see `sss_ssh_authorizedkeys`)

## Building

Clone this repository and configure/build with
```
./configure --with-github --without-samba --without-python2-bindings --without-python3-bindings
make
```
This will create `.libs/libsss_github.so`, which you need to copy to `/usr/lib/x86_64-linux-gnu/sssd/` (on Ubuntu,
paths for other systems may vary).

## Configuration

Here is an exmaple configuration:
```
[nss]
filter_groups = root,adm,sudo,shadow,staff,admin
filter_users = root
reconnection_retries = 3

[sssd]
config_file_version = 2
reconnection_retries = 3
sbus_timeout = 30
services = nss, pam, ssh
domains = users.github.com

[domain/users.github.com]
enumerate = false
cache_credentials = true
case_sensitive = preserving

id_provider = github
github_key = <github_key>

access_provider = simple
simple_allow_groups = SSSD
simple_allow_users = octocat
```

This configuration allows connection by any member of the `SSSD` GitHub organization or
the `octocat` user. The `<github_key>` should be set to a personal access token, and is
generally needed only to avoid GitHub rate limits. However, if you want to allow members
that have not set their membership to public, the personal access token will have to have
`read:org` scope for any organization that the SSSD provider needs to inspect.
