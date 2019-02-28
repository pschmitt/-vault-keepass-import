Release Notes
=============

Version 2.0.0
~~~~~~~~~~~~~

Version 2.0.0 introduces the following breaking changes:

* rewriting the keys is no longer the default, it is only done if --rewrite-key is set
* --vault is now --address and -v is the same as --verbose
* --ssl-no-verify is now --tls-skip-verify and -k does not exist
* the Vault token is no longer prompted interactively if it is not set in the environment or via --token
* the value of --token is no longer read from a file if it happens to be a valid file name
* --path is now --mount-point
