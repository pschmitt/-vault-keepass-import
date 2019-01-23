from setuptools import find_packages, setup


setup(
    name="vault-keepass-import",
    version="0.0.0",
    license="GPL3",
    description="UNMAINTAINED python cli to import a keepass database into vault",
    long_description=open("README.md").read(),
    author="Philipp Schmitt & al",
    author_email="philipp@schmitt.co",
    url="https://github.com/pschmitt/vault-keepass-import",
    packages=find_packages(),
    install_requires=open('requirements.txt').read().splitlines(),
)
