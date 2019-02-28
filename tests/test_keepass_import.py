import argparse
from vault_keepass_import import main
import hvac
import logging
import mock
import pytest
import base64


def verify_withattachment(vault_server, kv_version):
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    if kv_version == '2':
        entry = client.secrets.kv.v2.read_secret_version(
            'keepass/withattachment')['data']['data']
    else:
        entry = client.secrets.kv.v1.read_secret(
            'keepass/withattachment')['data']
    assert entry['0/attached.txt'] == base64.b64encode(
        "CONTENT\n".encode('ascii')).decode('ascii')
    assert entry['custom_property1'] == 'custom_value1'
    assert entry['notes'] == 'note2'
    assert entry['password'] == 'password2'
    assert entry['url'] == 'url2'
    assert entry['username'] == 'user2'
    assert 'Notes' not in entry


def verify_expected_secrets_no_rewrite(results, state):
    assert results == {
        'keepass/A#B%C*D+E(F\\G[éà': state,
        'keepass/Group1/title1group1': state,
        'keepass/Group1/Group1a/title1group1a': state,
        'keepass/withattachment': state,
        'keepass/title1 (TJxu0nxlyEuaKYNYpi0NPQ==)': state,
        'keepass/title1 (kFl/iRsoVUWDUdmmCDXwJg==)': state,
        'keepass/Trailing whitespace1     /Trailing whitespace2 /Trailing whitespace3 ': state,
    }


def verify_expected_secrets(results, state):
    assert results == {
        'keepass/A_B_C_D_E_F_G_éà': state,
        'keepass/Group1/title1group1': state,
        'keepass/Group1/Group1a/title1group1a': state,
        'keepass/withattachment': state,
        'keepass/title1 (TJxu0nxlyEuaKYNYpi0NPQ==)': state,
        'keepass/title1 (kFl/iRsoVUWDUdmmCDXwJg==)': state,
        'keepass/Trailing whitespace1/Trailing whitespace2/Trailing whitespace3': state,
    }


def test_export_to_vault_imports_expected_fields(vault_server):
    args = mock.MagicMock()
    args.token = vault_server['token']
    args.address = vault_server['http']
    args.dry_run = None
    args.kv_version = None
    args.mount_point = 'secret'

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_prefix='keepass/',
        args=args)

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_withattachment(vault_server, '2')


def test_delete_less_qualified_path(vault_server):
    args = mock.MagicMock()
    args.token = vault_server['token']
    args.address = vault_server['http']
    args.dry_run = None
    args.kv_version = None
    args.mount_point = 'secret'

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_prefix='keepass/',
        args=args)

    less_qualified = 'keepass/title1'
    importer.kv.create_or_update_secret(less_qualified, {'something': 'else'}, cas=None)

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_withattachment(vault_server, '2')

    with pytest.raises(hvac.exceptions.InvalidPath):
        importer.kv.read_secret(less_qualified, version=None)


def test_export_to_vault_no_rewrite_key(vault_server):
    args = mock.MagicMock()
    args.token = vault_server['token']
    args.address = vault_server['http']
    args.dry_run = None
    args.kv_version = None
    args.mount_point = 'secret'

    args.rewrite_key = None

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_prefix='keepass/',
        args=args)

    verify_expected_secrets_no_rewrite(importer.export_to_vault(), 'new')
    verify_expected_secrets_no_rewrite(importer.export_to_vault(), 'ok')


def test_export_to_vault_rewrite_key(vault_server, caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    caplog.set_level(logging.INFO, 'vault_keepass_import')

    args = mock.MagicMock()
    args.token = vault_server['token']
    args.address = vault_server['http']
    args.dry_run = None
    args.kv_version = None
    args.mount_point = 'secret'

    args.rewrite_key = True

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_prefix='keepass/',
        args=args)

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_expected_secrets(importer.export_to_vault(), 'ok')


def test_erase(vault_server, caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')

    args = mock.MagicMock()
    args.token = vault_server['token']
    args.address = vault_server['http']
    args.dry_run = None
    args.kv_version = None
    args.rewrite_key = True
    args.mount_point = 'secret'

    prefix = 'keepass/'

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_prefix=prefix,
        args=args)

    importer.set_verbosity(True)

    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    importer.export_to_vault()
    keys = client.secrets.kv.v2.list_secrets(prefix)['data']['keys']
    assert 'Group1/' in keys
    assert 'withattachment' in keys
    importer.kv.erase(importer.prefix)
    with pytest.raises(hvac.exceptions.InvalidPath):
        client.secrets.kv.v2.list_secrets(prefix)


def test_export_info():
    assert main.Importer.export_info('ok', 'PATH', {}, {}) == 'ok: PATH'
    assert main.Importer.export_info('changed', 'PATH', {
        'removed1': 'v1',
        'removed2': 'v2',
        'identical': 'v3',
        'different': 'K1',
    }, {
        'identical': 'v3',
        'different': 'K2',
        'added1': 'v4',
        'added2': 'v4',
    }) == 'changed: PATH added added1 added2, removed removed1 removed2, changed different'


def test_get_path():
    prefix = 'PREFIX/'  # guaranteed to end with a / by the Importer constructor
    entry = mock.MagicMock()
    entry.title = 'TITLE'
    entry.parentgroup.path = 'GROUP'
    assert main.Importer.get_path(prefix, entry) == 'PREFIX/GROUP/TITLE'
    entry.parentgroup.path = '/'
    assert main.Importer.get_path(prefix, entry) == 'PREFIX/TITLE'


def test_parser():
    parser = main.parser()
    assert type(parser) == argparse.ArgumentParser
    with pytest.raises(SystemExit):
        parser.parse_args(['--version'])


def test_parse_args(mocker):
    token_value = 'TOKEN'
    password_value = 'PASSWORD'
    (args, password) = main.parse_args([
        'db.kdbx', '--password', password_value, '--token', token_value
    ])
    assert args.token == token_value
    assert args.password == password_value

    getpass = mocker.patch('getpass.getpass')
    (args, password) = main.parse_args([
        'db.kdbx', '--token', token_value,
    ])
    getpass.assert_called_once_with('KeePass password: ')
