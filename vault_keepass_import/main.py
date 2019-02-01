#!/usr/bin/env python
# coding: utf-8


from __future__ import print_function
from __future__ import unicode_literals
import argparse
import base64
import collections
import getpass
import hvac
from pykeepass import PyKeePass
import logging
import os


logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class Importer(object):

    def __init__(self,
                 keepass_db, keepass_password, keepass_keyfile,
                 vault_url, vault_token, vault_prefix, cert, verify,
                 dry_run=False,
                 version=None,
                 path='secret/'):
        self.dry_run = dry_run
        self.path = path
        if not self.path.endswith('/'):
            self.path += '/'
        self.prefix = vault_prefix
        if not self.prefix.endswith('/'):
            self.prefix += '/'
        self.keepass = PyKeePass(keepass_db, password=keepass_password, keyfile=keepass_keyfile)
        self.open_vault(vault_url, vault_token, cert, verify, version)

    def open_vault(self, vault_url, vault_token, cert, verify, version):
        self.vault = hvac.Client(url=vault_url, token=vault_token, cert=cert, verify=verify)
        if version:
            self.vault_kv_version = version
        else:
            mounts = self.vault.sys.list_mounted_secrets_engines()['data']
            assert self.path in mounts, f'path {self.path} is not founds in mounts {mounts}'
            self.vault_kv_version = mounts[self.path]['options']['version']

    @staticmethod
    def set_verbosity(verbose):
        if verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO
        logging.getLogger('vault_keepass_import').setLevel(level)

    @staticmethod
    def get_path(prefix, entry):
        path = entry.parentgroup.path
        if path[0] == '/':
            return prefix + entry.title
        else:
            return prefix + path + '/' + entry.title

    def export_entries(self, force_lowercase):
        entries = collections.defaultdict(list)
        kp = self.keepass
        for entry in kp.entries:
            k = self.get_path(self.prefix, entry)
            if force_lowercase:
                k = k.lower()
            v = self.keepass_entry_to_dict(entry)
            entries[k].append(v)
        logger.info('Total entries: {}'.format(len(entries)))
        uniq_entries = {}
        for k, vs in entries.items():
            if len(vs) == 1:
                uniq_entries[k] = vs[0]
            else:
                for v in vs:
                    uniq_entries[(k, v['uuid'])] = v
        return uniq_entries

    def delete_secret(self, path):
        if self.vault_kv_version == '2':
            if not self.dry_run:
                self.vault.secrets.kv.v2.delete_metadata_and_all_versions(path)
        else:
            if not self.dry_run:
                self.vault.secrets.kv.v1.delete_secret(path)

    def erase(self, prefix):
        try:
            if self.vault_kv_version == '2':
                self.vault.secrets.kv.v2.list_secrets(prefix)
            else:
                self.vault.secrets.kv.v1.list_secrets(prefix)
        except hvac.exceptions.InvalidPath:
            return
        self._erase(prefix)

    def _erase(self, prefix):
        if self.vault_kv_version == '2':
            keys = self.vault.secrets.kv.v2.list_secrets(prefix)['data']['keys']
        else:
            keys = self.vault.secrets.kv.v1.list_secrets(prefix)['keys']
        for key in keys:
            path = prefix + key
            if path.endswith('/'):
                self._erase(path)
            else:
                logger.debug(f'erase {path}')
                self.delete_secret(path)

    @staticmethod
    def keepass_entry_to_dict(e):
        entry = {}
        for k in ('username', 'password', 'url', 'notes', 'tags', 'icon', 'uuid'):
            if getattr(e, k):
                entry[k] = getattr(e, k)
        custom_properties = e.custom_properties
        # remove this workaround when https://github.com/pschmitt/pykeepass/pull/138 is merged
        if 'Notes' in custom_properties:
            del custom_properties['Notes']
        entry.update(custom_properties)
        if e.expires:
            entry['expiry_time'] = str(e.expiry_time.timestamp())
        for k in ('ctime', 'atime', 'mtime'):
            if getattr(e, k):
                entry[k] = str(getattr(e, k).timestamp())
        if hasattr(e, 'attachments'):  # implemented in pykeepass >= 3.0.3
            for a in e.attachments:
                entry[f'{a.id}/{a.filename}'] = base64.b64encode(a.data).decode('ascii')
        return entry

    @staticmethod
    def export_info(state, path, old, new):
        if state == 'ok':
            impacted = ''
        else:
            info = []
            added = sorted(set(new.keys()) - set(old.keys()))
            if added:
                info.append(f'added {" ".join(added)}')
            removed = sorted(set(old.keys()) - set(new.keys()))
            if removed:
                info.append(f'removed {" ".join(removed)}')
            changed = []
            for k in sorted(set(old.keys()) & set(new.keys())):
                if old[k] != new[k]:
                    changed.append(k)
            if changed:
                info.append(f'changed {" ".join(changed)}')
            impacted = f' {", ".join(info)}'
        return f'{state}: {path}{impacted}'

    def read_secret(self, path):
        if self.vault_kv_version == '2':
            return self.vault.secrets.kv.v2.read_secret_version(path)['data']['data']
        else:
            return self.vault.secrets.kv.v1.read_secret(path)['data']

    @staticmethod
    def get_path_from_path_uuid(path_uuid):
        if type(path_uuid) is str:
            return path_uuid
        else:
            return f'{path_uuid[0]} ({path_uuid[1]})'

    def get_existing(self, path_uuid):
        path = self.get_path_from_path_uuid(path_uuid)
        try:
            exists = self.read_secret(path)
        except hvac.exceptions.InvalidPath:
            exists = {}
        except Exception:
            raise
        return (path, exists)

    def delete_less_qualified_path(self, path_uuid):
        # if path_uuid is a string, there is no uuid therefore nothing to look for
        if type(path_uuid) is str:
            return
        # if the unqualified_path exists, remove it
        unqualified_path = path_uuid[0]
        (path, exists) = self.get_existing(unqualified_path)
        if exists:
            self.delete_secret(unqualified_path)

    def create_or_update_secret(self, path, entry):
        if self.vault_kv_version == '2':
            self.vault.secrets.kv.v2.create_or_update_secret(path, entry)
        else:
            self.vault.secrets.kv.v1.create_or_update_secret(path, entry)

    def export_to_vault(self, force_lowercase=False):
        entries = self.export_entries(force_lowercase)
        r = {}
        for path_uuid, entry in entries.items():
            (path, exists) = self.get_existing(path_uuid)
            if exists:
                r[path] = entry == exists and 'ok' or 'changed'
            else:
                r[path] = 'new'
            logger.info(self.export_info(r[path], path, exists, entry))
            if not self.dry_run and r[path] in ('changed', 'new'):
                self.create_or_update_secret(path, entry)
            self.delete_less_qualified_path(path_uuid)
        return r


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--verbose',
        action='store_true',
        required=False,
        help='Verbose mode'
    )
    parser.add_argument(
        '-p', '--password',
        required=False,
        help='Password to unlock the KeePass database'
    )
    parser.add_argument(
        '--kv-version',
        choices=['1', '2'],
        required=False,
        help='Force the Vault KV backend version (1 or 2). Autodetect if not set.'
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
        '--dry-run',
        action='store_true',
        required=False,
        help='Show what would be done but do nothing'
    )
    parser.add_argument(
        '--ca-cert',
        required=False,
        help=("Path on the local disk to a single PEM-encoded CA certificate to verify "
              "the Vault server's SSL certificate.")
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
        '--prefix',
        default='keepass/',
        help='Vault prefix (destination of the import)'
    )
    parser.add_argument(
        '--path',
        default='secret/',
        help='KV mount point',
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

    if args.ssl_no_verify:
        verify = False
    else:
        if args.ca_cert:
            verify = args.ca_cert
        else:
            verify = True

    importer = Importer(
        keepass_db=args.KDBX,
        keepass_password=password,
        keepass_keyfile=args.keyfile,
        vault_url=args.vault,
        vault_token=token,
        vault_prefix=args.prefix,
        cert=(args.client_cert, args.client_key),
        verify=verify,
        path=args.path,
        version=args.kv_version,
        dry_run=args.dry_run,
    )
    importer.set_verbosity(args.verbose)
    if args.erase:
        importer.erase(importer.prefix)
    importer.export_to_vault(
        force_lowercase=args.lowercase,
    )
