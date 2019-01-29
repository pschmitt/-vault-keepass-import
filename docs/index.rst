Import KeePass secrets in Hashicorp Vault
=========================================

`vault-keepass-import
<https://lab.enough.community/singuliere/vault-keepass-import>`_ is a
CLI to import `KeePass <https://keepass.info/>`_ secrets (using
`pykeepass <https://github.com/pschmitt/pykeepass>`_) in `Hashicorp
Vault <https://learn.hashicorp.com/vault/getting-started/install>`_
(using `hvac <https://hvac.readthedocs.io>`_).

Bugs and feature requests can be found `in the issue tracker
<https://lab.enough.community/singuliere/vault-keepass-import/issues>`_

Quick start
~~~~~~~~~~~

.. code::

   $ pip3 install vault-keepass-import
   $ export VAULT_ADDR=https://myvault.com:8200
   $ export VAULT_TOKEN=mytoken
   $ vault-keepass-import --token $VAULT_TOKEN \
			  --vault $VAULT_ADDR \
			  --password kdbxpassword \
			  database.kdbx
   $ vault kv list secret/keepass
   Keys
   ----
   Group1/
   Group2/
   secret1
   secret2
   $ vault kv get secret/keepass/secret1
   ====== Metadata ======
   Key              Value
   ---              -----
   created_time     2019-01-29T13:52:32.79894513Z
   deletion_time    n/a
   destroyed        false
   version          1
   ==== Data ====
   Key      Value
   ---      -----
   atime    1465498383
   ctime    1465498332
   icon     0
   mtime       1527099465
   password    strongpassword
   username    someuser
   uuid        5uCDWvHUQjyGnyBlRw9CFA==

Testing the import
~~~~~~~~~~~~~~~~~~

* Download and `install Hashicorp Vault <https://learn.hashicorp.com/vault/getting-started/install>`_
* Run vault in development mode (the storage is reset when it restarts)

  .. code::

     $ vault server -dev
     ...
     Root Token: s.PTNNfrICGosELrJeX2ojPIS6
     ...

* Assuming the password to the KeePass database is `kdbxpassword`, run an import with:

  .. code::

     $ vault-keepass-import --token s.PTNNfrICGosELrJeX2ojPIS6 \
			    --vault http://127.0.0.1:8200 \
			    --password kdbxpassword \
			    database.kdbx

Command help
~~~~~~~~~~~~

.. code::

   vault-keepass-import --help

Reference
=========

Data conversion
~~~~~~~~~~~~~~~

* `mtime`, `ctime`, `atime` are always imported and converted to `epoch <https://en.wikipedia.org/wiki/Unix_time>`_
* `expiry_time` is only imported if set and converted to `epoch <https://en.wikipedia.org/wiki/Unix_time>`_
* `username`, `password`, `url`, `notes`, `tags`, `uuid` are imported as is
* `attachments` are imported with a key set to **id/filename** and the value as is (for instance if there only is one **foo.txt** attachment, it will have the key **0/foo.txt**)

Contributions
=============

.. toctree::
  :maxdepth: 2

  development
