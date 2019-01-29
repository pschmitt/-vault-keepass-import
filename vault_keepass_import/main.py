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


def get_path(vault_backend, entry):
    path = entry.parentgroup.path
    if path[0] == '/':
        return vault_backend + '/' + entry.title
    else:
        return vault_backend + '/' + path + '/' + entry.title


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
                        cert=None, ssl_verify=True):
    client = hvac.Client(
        url=vault_url, token=vault_token, cert=cert, verify=ssl_verify
    )
    try:
        client.sys.disable_secrets_engine(path=vault_backend)
    except hvac.exceptions.InvalidRequest as e:
        if e.message == 'no matching mount':
            logging.debug('Could not delete backend: Mount point not found.')
        else:
            raise
    client.sys.enable_secrets_engine(backend_type='kv', path=vault_backend)


def get_next_similar_entry_index(vault_url, vault_token, entry_name, cert=None, ssl_verify=True):
    client = hvac.Client(url=vault_url, token=vault_token, cert=cert, verify=ssl_verify)
    index = 0
    try:
        title = os.path.basename(entry_name)
        children = client.secrets.kv.v2.list_secrets(os.path.dirname(entry_name))
        for child in children['data']['keys']:
            m = re.match(title + r' \((\d+)\)$', child)
            if m:
                index = max(index, int(m.group(1)))
    except hvac.exceptions.InvalidPath:
        pass
    except Exception:
        raise
    return index + 1


def generate_entry_path(vault_url, vault_token, entry_path,
                        cert=None, ssl_verify=True):
    next_entry_index = get_next_similar_entry_index(
        vault_url, vault_token, entry_path, cert, ssl_verify
    )
    new_entry_path = '{} ({})'.format(entry_path, next_entry_index)
    logger.info(
        'Entry "{}" already exists, '
        'creating a new one: "{}"'.format(entry_path, new_entry_path)
    )
    return new_entry_path


def keepass_entry_to_dict(e):
    entry = {}
    for k in ('username', 'password', 'url', 'notes', 'tags', 'icon', 'uuid'):
        if getattr(e, k):
            entry[k] = getattr(e, k)
    if e.expires:
        entry['expiry_time'] = e.expiry_time.timestamp()
    for k in ('ctime', 'atime', 'mtime'):
        if getattr(e, k):
            entry[k] = getattr(e, k).timestamp()
    for a in e.attachments:
        entry[f'{a.id}/{a.filename}'] = a.data.decode('utf-8')
    return entry


def vault_entry_to_dict(e):
    return e['data']['data']


def export_to_vault(keepass_db, keepass_password, keepass_keyfile,
                    vault_url, vault_token, vault_backend, cert=None, ssl_verify=True,
                    force_lowercase=False, skip_root=False, allow_duplicates=True):
    entries = export_entries(
        keepass_db, keepass_password, keepass_keyfile,
        skip_root
    )
    client = hvac.Client(
        url=vault_url, token=vault_token, cert=cert, verify=ssl_verify
    )
    r = {}
    for e in entries:
        entry = keepass_entry_to_dict(e)
        entry_path = get_path(vault_backend, e)
        if force_lowercase:
            entry_path = entry_path.lower()
        logger.debug(f'INSERT {entry_path} {entry}')
        try:
            exists = client.secrets.kv.v2.read_secret_version(entry_path)
        except hvac.exceptions.InvalidPath:
            exists = None
        except Exception:
            raise
        if allow_duplicates:
            if exists:
                entry_path = generate_entry_path(
                    vault_url, vault_token, entry_path, cert, ssl_verify)
            r[entry_path] = 'changed'
        else:
            if exists:
                r[entry_path] = entry == vault_entry_to_dict(exists) and 'ok' or 'changed'
            else:
                r[entry_path] = 'changed'
        logger.info(f'{r[entry_path]}: {entry_path} => {entry}')
        if r[entry_path] == 'changed':
            client.secrets.kv.v2.create_or_update_secret(entry_path, entry)
    return r


def main():
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
        '--client-cert',
        required=False,
        help='client cert file'
    )
    parser.add_argument(
        '--client-key',
        required=False,
        help='client key file'
    )
    parser.add_argument(
        '--idempotent',
        action='store_true',
        required=False,
        help='An entry is overriden if it already exists, unless it is up to date'
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
            cert=(args.client_cert, args.client_key),
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
        cert=(args.client_cert, args.client_key),
        ssl_verify=not args.ssl_no_verify,
        force_lowercase=args.lowercase,
        skip_root=args.skip_root,
        allow_duplicates=not args.idempotent
    )
