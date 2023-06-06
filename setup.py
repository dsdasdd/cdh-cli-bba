from setuptools import find_packages
from setuptools import setup

setup(
    name="cdh",
    use_scm_version=True,
    packages=(find_packages(include=["cdh_utils", "migrate_config"])),
    include_package_data=True,
    py_modules=["cdh"],
    install_requires=[
        "beautifulsoup4",
        "urllib3",
        "lxml",
        "pysocks",
        # get a recent version of click from their repository, not an official release as some features were needed
        # for the autocomplete (bugs in the older version) and the Click team was not able to provide a clear release
        # schedule.
        "click>=8.0.3",
        "boto3",
        "requests",
        "configparser",
        "ruamel.yaml",
        "keyring",
        "tabulate",
        "click-spinner",
        "aws-requests-auth",
        "semver",
        "polling2",
        "importlib_metadata",  # TODO: remove once we raise the Python minimum version to 3.8
    ],
    entry_points="""
        [console_scripts]
        cdh=cdh:cli
    """,
    python_requires=">=3.7",
    setup_requires="setuptools_scm",
)
