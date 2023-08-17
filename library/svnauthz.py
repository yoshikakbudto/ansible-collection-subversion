#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Generates authz file for svn repo.

"""
import logging
import ansible.module_utils.Authz as Authz
import ansible.module_utils.Config as Config
from ansible.module_utils.basic import AnsibleModule


def main():
    """main func."""
    logging.basicConfig(format='[%(levelname)s] %(message)s')
    logging.getLogger().setLevel(logging.DEBUG)
    arguments = dict(
            ldap=dict(required=True),
            authz_path=dict(required=False, default=None),
            repo_name=dict(required=True),
            repos_root=dict(required=False, default='/mnt/svn'),
            enable_debug=dict(required=False, default=False),
            access=dict(required=True)
        )
    module = AnsibleModule(
        argument_spec=arguments,
        supports_check_mode=True
    )
    Config.load(module)
    Authz.load()
    Authz.save(module)

if __name__ == "__main__":
    main()
