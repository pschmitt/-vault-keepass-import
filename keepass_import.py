#!/usr/bin/env python
# coding: utf-8


from __future__ import print_function
from __future__ import unicode_literals
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import getpass
import hvac
from pykeepass import PyKeePass
import logging
import os
import re
import requests


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Disable logging for requests and urllib3
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_path(entry):
    path = entry.parentgroup.path
    if path[0] == '/':
        return entry.title
    else:
        return path + '/' + entry.title


def export_entries(filename, password, keyfile=None, skip_root=False):
    all_entries = []
    with PyKeePass(filename, password=password, keyfile=keyfile) as kp:
        for entry in kp.entries:
            if skip_root and entry.parentgroup.path == '/':
                continue
            all_entries.append(entry)
    logger.info('Total entries: {}'.format(len(all_entries)))
    return all_entries


def reset_vault_backend(vault_url, vault_token, vault_backend,
                        ssl_verify=True):
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    try:
        client.sys.disable_secrets_engine(path=vault_backend)
    except hvac.exceptions.InvalidRequest as e:
        if e.message == 'no matching mount':
            logging.debug('Could not delete backend: Mount point not found.')
        else:
            raise
    client.sys.enable_secrets_engine(backend_type='kv', path=vault_backend)


def find_similar_entries(vault_url, vault_token, entry_name, ssl_verify=True):
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    entry = client.read(entry_name)
    entries = [entry] if entry else []
    index = 2
    while True:
        entry = client.read('{} ({})'.format(entry_name, index))
        if entry:
            entries.append(entry)
        else:
            return entries
        index += 1


def get_next_similar_entry_index(vault_url, vault_token, entry_name,
                                 ssl_verify=True):
    return len(find_similar_entries(
        vault_url, vault_token, entry_name, ssl_verify
    )) + 1


def export_to_vault(keepass_db, keepass_password, keepass_keyfile,
                    vault_url, vault_token, vault_backend, ssl_verify=True,
                    force_lowercase=False, skip_root=False):
    entries = export_entries(
        keepass_db, keepass_password, keepass_keyfile, force_lowercase,
        skip_root
    )
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    ignored_indexes = [
        '_entry_name', '_path',
        'title' if force_lowercase else 'Title'
    ]
    for e in entries:
        cleaned_entry = {k: v for k, v in e.items() if k not in ignored_indexes}
        entry_path = '{}/{}{}'.format(
            vault_backend,
            e['_path'] + '/' if e['_path'] else '',
            e['_entry_name']
        )
        logger.debug(
            'INSERT: "{}" to "{}"'.format(
                e['_entry_name'],
                entry_path
            )
        )
        if client.read(entry_path):
            # There already is an entry at this path
            next_entry_index = get_next_similar_entry_index(
                vault_url, vault_token, entry_path, ssl_verify
            )
            new_entry_path = '{} ({})'.format(entry_path, next_entry_index)
            logger.info(
                'Entry "{}" already exists, '
                'creating a new one: "{}"'.format(entry_path, new_entry_path)
            )
            entry_path = new_entry_path
        return client.secrets.kv.v2.create_or_update_secret(
            entry_path,
            cleaned_entry
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p', '--password',
        required=False,
        help='Password to unlock the KeePass database'
    )
    parser.add_argument(
        '-f', '--keyfile',
        required=False,
        help='Keyfile to unlock the KeePass database'
    )
    parser.add_argument(
        '-t', '--token',
        required=False,
        default=os.getenv('VAULT_TOKEN', None),
        help='Vault token'
    )
    parser.add_argument(
        '-v', '--vault',
        default=os.getenv('VAULT_ADDR', 'https://localhost:8200'),
        required=False,
        help='Vault URL'
    )
    parser.add_argument(
        '-k', '--ssl-no-verify',
        action='store_true',
        default=True if os.getenv('VAULT_SKIP_VERIFY', False) else False,
        required=False,
        help='Whether to skip TLS cert verification'
    )
    parser.add_argument(
        '-s', '--skip-root',
        action='store_true',
        required=False,
        help='Skip KeePass root folder (shorter paths)'
    )
    parser.add_argument(
        '-b', '--backend',
        default='keepass',
        help='Vault backend (destination of the import)'
    )
    parser.add_argument(
        '-e', '--erase',
        action='store_true',
        help='Erase the prefix prior to the import operation'
    )
    parser.add_argument(
        '-l', '--lowercase',
        action='store_true',
        help='Force keys to be lowercased'
    )
    parser.add_argument(
        'KDBX',
        help='Path to the KeePass database'
    )
    args = parser.parse_args()

    password = args.password if args.password else getpass.getpass()
    if args.token:
        # If provided argument is a file read from it
        if os.path.isfile(args.token):
            with open(args.token, 'r') as f:
                token = filter(None, f.read().splitlines())[0]
        else:
            token = args.token
    else:
        token = getpass.getpass('Vault token: ')

    if args.erase:
        reset_vault_backend(
            vault_url=args.vault,
            vault_token=token,
            ssl_verify=not args.ssl_no_verify,
            vault_backend=args.backend
        )
    export_to_vault(
        keepass_db=args.KDBX,
        keepass_password=password,
        keepass_keyfile=args.keyfile,
        vault_url=args.vault,
        vault_token=token,
        vault_backend=args.backend,
        ssl_verify=not args.ssl_no_verify,
        force_lowercase=args.lowercase,
        skip_root=args.skip_root
    )
