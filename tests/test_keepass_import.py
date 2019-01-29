from vault_keepass_import import main
import pytest
import requests


def test_export_to_vault_duplicates(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'])

    r0 = run_import()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    r1 = run_import()
    assert r1 == {'keepass/title1 (1)': 'changed',
                  'keepass/Group1/title1group1 (1)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (1)': 'changed',
                  'keepass/withattachement (1)': 'changed'}
    r2 = run_import()
    assert r2 == {'keepass/title1 (2)': 'changed',
                  'keepass/Group1/title1group1 (2)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (2)': 'changed',
                  'keepass/withattachement (2)': 'changed'}


def test_export_to_vault_no_duplicates(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            allow_duplicates=False)

    r1 = run_import()
    assert r1 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    # converged
    r2 = run_import()
    assert all(map(lambda x: x == 'ok', r2.values()))
    assert r1.keys() == r2.keys()
    # idempotent
    r3 = run_import()
    assert r2 == r3


def test_export_to_vault_reset(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'])

    r0 = run_import()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    main.reset_vault_backend(vault_url=vault_server['http'],
                             vault_token=vault_server['token'],
                             vault_backend='secrets')
    r1 = run_import()
    assert r1 == {'keepass/title1 (1)': 'changed',
                  'keepass/Group1/title1group1 (1)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (1)': 'changed',
                  'keepass/withattachement (1)': 'changed'}


def test_client_cert(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['https'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            ssl_verify=False,
            cert=(vault_server['crt'], vault_server['key']))

    r0 = run_import()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}

    with pytest.raises(requests.exceptions.SSLError):
        main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['https'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            ssl_verify=False)
