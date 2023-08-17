#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Do funny stuff with authz."""


import sys
import os
import chardet
import logging
import difflib
from ansible.module_utils.Config import CONFIG, AUTHZ

from ldap3 import Server, Connection, ALL

def decode_text(text):
    """Try to automatically find encoding and decode given text."""
    encoding = None
    if isinstance(text, bytes):
       detected = chardet.detect(text)
       encoding = detected['encoding']

    if encoding:
        return(text.decode(encoding))
    else:
        return(text)


def load():
    """Loads repo access config to internal structure."""

    server = Server(CONFIG['ldap']['url'], get_info=ALL)
    try:
        conn = Connection(server, CONFIG['ldap']['bind_dn'], CONFIG['ldap']['bind_pw'],
                          auto_bind=True, check_names=False, auto_encode=True)
    except (ldap3.core.exceptions.LDAPSocketOpenError,
            ldap3.core.exceptions.LDAPBindError):
        raise Exception("[ERROR] failed to bind to '{}' with dn: {}}\n".format(CONFIG['ldap']['url'], CONFIG['ldap']['bind_dn']))


    AUTHZ['access']['*'] = CONFIG['svn']['default_everyone_perms']

    for obj, objparams in CONFIG['svn']['access'].items():
        if CONFIG['debug']:
            logging.debug(f"Getting svn-accesses for {obj}")

        if obj == 'DEFAULT_GROUP':
            group_name = CONFIG['svn']['default_groupname_pfx'] + CONFIG['svn']['repo_name']
            try:
                perms = objparams
            except NameError:
                if CONFIG['debug']:
                    logging.debug(f"using default value ({CONFIG['svn']['default_perms']}) for {group_name}")

                perms = CONFIG['svn']['default_perms']
            store_group_access(conn, perms, group_name)

        elif obj == 'FOOTER':
            CONFIG['svn']['authz_footer'] = objparams

        elif obj in ['EVERYONE', 'ANYONE', 'ANYBODY', 'EVERYBODY', 'ALL', 'ANY', 'DEFAULT', '*']:
            try:
                perms = objparams
            except NameError:
                if CONFIG['debug']:
                    logging.debug(f"using default value ({CONFIG['svn']['default_everyone_perms']}) for '*'")
                perms = CONFIG['svn']['default_everyone_perms']

            AUTHZ['access']['*'] = perms

        else:
            if not isinstance(objparams, dict):
                print("[ERROR] '%s' should be either a predefined clause or has "
                      "a dictionary values like 'type' and 'perms', given: '%s'"
                      % (obj, objparams))
                sys.exit(1)

            if 'type' not in objparams:
                print("[ERROR] '%s' has no type and perms set. Given: '%s' "
                      % (obj, objparams))
                sys.exit(1)

            try:
                perms = objparams['perms']
            except KeyError:
                if CONFIG['debug']:
                    logging.debug(f"using default value ({CONFIG['svn']['default_perms']}) for {obj}")

                perms = CONFIG['svn']['default_perms']

            if objparams['type'] == 'group':
                group_name = obj
                store_group_access(conn, perms, group_name)
            elif objparams['type'] == 'user':
                AUTHZ['access'][obj] = perms
            else:
                print("[ERROR] unsupported object type (%s) in %s "
                      % (objparams['type'], obj))
    if CONFIG['debug']:
        logging.debug(AUTHZ)


def store_group_access(conn, perms, group_name):
    """Update AUTHZ dict with group accesses and members."""

    AUTHZ['access']['@'+group_name] = perms

    r = get_members(conn, group_name)
    r['users'].sort()
    # store group name even if it has not any users.
    AUTHZ['groups'][group_name] = r['users']

    if CONFIG['ldap']['group_traversal'] and r['groups']:
        for subgroup in r['groups']:
            # perm are enherited from above
            AUTHZ['access']['@'+group_name+'_'+subgroup] = perms
            r = get_members(conn, subgroup)
            AUTHZ['groups'][group_name+'_'+subgroup] = r['users']


def get_members(conn, group):
    """Return dict of users and groups lists."""
    result = {'users': [], 'groups': []}

    conn.search(CONFIG['ldap']['search_dn'],
                "(&(objectclass=group)(cn=%s))" % group,
                attributes=['member'])
    try:
        if len(conn.entries[0]['member']) == 0:
            print("[WARN] the group %s has no members :(" % group)
    except IndexError:
        raise Exception(f"[ERROR] the group '{group}' was not found in LDAP. And no custom config found")

    for cn in conn.entries[0]['member']:
        # collect user members by filter
        conn.search(cn, CONFIG['ldap']['user_query'],
                    attributes=[CONFIG['ldap']['objid_attribute']])
        try:
            result['users'] += conn.entries[0][CONFIG['ldap']['objid_attribute']]
        except IndexError:
                #Seems like {cn} is not a USER
                pass

        # collect group members if needed
        if CONFIG['ldap']['group_traversal']:
            conn.search(cn, '(objectclass=group)', attributes=['cn'])
            try:
                result['groups'] += conn.entries[0]['cn']
            except IndexError:
                if CONFIG['debug']:
                    #Seems like {cn} is not a GROUP
                    pass
    return result

def save(module):
    """authz_paths authz to file or STDOUT."""

    authz_content = CONFIG['svn']['authz_header']
    authz_content += "\n[groups]"

    for group, members in AUTHZ['groups'].items():
        authz_content += '\n' + group + ' = ' + ', '.join(members)

    authz_content += '\n\n[/]'

    for obj, perm in AUTHZ['access'].items():
        if not obj == '*':
            authz_content += '\n' + obj + ' = ' + perm

    authz_content += '\n* = ' + AUTHZ['access']['*']
    authz_content += '\n' + CONFIG['svn']['authz_footer']

    if CONFIG['svn']['authz_path']:
        authz_path = CONFIG['svn']['authz_path']
    else:
        authz_path = CONFIG['svn']['repos_root'] + '/' + CONFIG['svn']['repo_name'] + '/conf/authz'

    if os.path.exists(authz_path):
        with open(authz_path, 'rb') as input:
            authz_existing = input.read()
        if CONFIG['debug']:
            with open(authz_path+'.prev', 'wb') as output:
                output.write(authz_existing)
    else:
        authz_existing = b"none"

    if authz_existing == authz_content.encode('utf-8'):
        module.exit_json(changed=False)

    if not module.check_mode:
        with open(authz_path, 'wb') as output:
            output.write(authz_content.encode('utf-8'))
    diff_a = decode_text(authz_existing).splitlines(keepends=True)
    diff_b = decode_text(authz_content).splitlines(keepends=True)
    diff = list(difflib.unified_diff(diff_a, diff_b, n=0, lineterm='\n'))
    module.exit_json(changed=True, msg=''.join(diff))
