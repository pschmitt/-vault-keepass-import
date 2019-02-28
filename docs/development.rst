Release management
==================

* Prepare a new version

 - version=1.3.0 ; perl -pi -e "s/^version.*/version = $version/" setup.cfg ; for i in 1 2 ; do python setup.py sdist ; amend=$(git log -1 --oneline | grep --quiet "version $version" && echo --amend) ; git commit $amend -m "version $version" ChangeLog setup.cfg ; git tag -a -f -m "version $version" $version ; done

* Publish a new version

 - twine upload --username singuliere --password "$PYPI_PASSWORD" dist/vault-keepass-import-1.3.0.tar.gz

* pypi maintenance

 - python setup.py register # if the project does not yet exist
 - trim old versions at https://pypi.python.org/pypi/vault-keepass-import
