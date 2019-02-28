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
from vault_keepass_import.version import __version__
import logging
import hvac_cli.kv
import hvac_cli.cmd
import sys


logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class Importer(object):

    def __init__(self,
                 keepass_db, keepass_password, keepass_keyfile,
                 vault_prefix,
                 args):
        self.args = args
        self.kv = hvac_cli.kv.kvcli_factory(args, args)
        self.kv.rewrite_key = False  # we do that ourselves
        self.prefix = vault_prefix
        if not self.prefix.endswith('/'):
            self.prefix += '/'
        self.keepass = PyKeePass(keepass_db, password=keepass_password, keyfile=keepass_keyfile)

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
            path = prefix + entry.title
        else:
            path = prefix + path + '/' + entry.title
        return path

    def export_entries(self, force_lowercase):
        entries = collections.defaultdict(list)
        kp = self.keepass
        for entry in kp.entries:
            k = self.get_path(self.prefix, entry)
            if self.args.rewrite_key:
                k = hvac_cli.kv.KVCLI.sanitize(k)
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

    @staticmethod
    def keepass_entry_to_dict(e):
        entry = {}
        for k in ('username', 'password', 'url', 'notes', 'tags', 'icon', 'uuid'):
            if getattr(e, k):
                entry[k] = getattr(e, k)
        custom_properties = e.custom_properties
        entry.update(custom_properties)
        if e.expires:
            entry['expiry_time'] = str(e.expiry_time.timestamp())
        for k in ('ctime', 'atime', 'mtime'):
            if getattr(e, k):
                entry[k] = str(getattr(e, k).timestamp())
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

    @staticmethod
    def get_path_from_path_uuid(path_uuid):
        if type(path_uuid) is str:
            return path_uuid
        else:
            return f'{path_uuid[0]} ({path_uuid[1]})'

    def get_existing(self, path_uuid):
        path = self.get_path_from_path_uuid(path_uuid)
        try:
            exists = self.kv.read_secret(path, version=None)
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
            self.kv.delete_metadata_and_all_versions(unqualified_path)

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
            if r[path] in ('changed', 'new'):
                self.kv.create_or_update_secret(path, entry, cas=None)
            self.delete_less_qualified_path(path_uuid)
        return r


def parser():
    parser = argparse.ArgumentParser()
    hvac_cli.cmd.HvacApp.set_parser_arguments(parser)
    hvac_cli.kv.KvCommand.set_rewrite_key(parser)
    hvac_cli.kv.KvCommand.set_common_options(parser)
    parser.add_argument(
        '--version', action='version', version=f'%(prog)s {__version__}'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        required=False,
        help='Verbose mode'
    )
    parser.add_argument(
        '-p', '--password',
        required=False,
        help='Password to unlock the KeePass database. Prompted interactively if not set.'
    )
    parser.add_argument(
        '-f', '--keyfile',
        required=False,
        help='Keyfile path to unlock the KeePass database'
    )
    parser.add_argument(
        '--prefix',
        default='keepass/',
        help='Vault prefix (destination of the import)'
    )
    parser.add_argument(
        '-e', '--erase',
        action='store_true',
        help='Erase the prefix (see --prefix) prior to the import operation'
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
    return parser


def parse_args(argv):
    args = parser().parse_args(argv)
    password = args.password if args.password else getpass.getpass('KeePass password: ')
    return (args, password)


def main():
    (args, password) = parse_args(sys.argv[1:])
    importer = Importer(
        keepass_db=args.KDBX,
        keepass_password=password,
        keepass_keyfile=args.keyfile,
        vault_prefix=args.prefix,
        args=args,
    )
    importer.set_verbosity(args.verbose)
    if args.erase:
        importer.kv.erase(importer.prefix)
    importer.export_to_vault(
        force_lowercase=args.lowercase,
    )
