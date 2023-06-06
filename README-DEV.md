# Developer Readme

## Setup for development and local execution 

### Virtual environment setup
- Use Python version 3.7+ (see [README.md](README.md))
- Create a virtualenv and activate it. Use of pyenv is recommended:

      pyenv install 3.7.9
      pyenv virtualenv 3.7.9 cdh_cli

### Install Dependencies

Install dependencies:

      pip install -r requirements-dev.txt

### Install Pre-commit Hooks

      pre-commit install
      pre-commit install --hook-type prepare-commit-msg

### Upgrade or Add Dependencies

New production dependencies must be added in `setup.py`, new test dependencies in `requirements-dev.txt`. Then run

      pip-compile --upgrade

and commit the re-generated `requirements.txt`.

### Local Development Installation

Install project as package with `cdh` executables:

     pip install --editable .

This will reflect local changes immediately.

### Running
- Running the tests:

      pytest

- Running style checker:

      pre-commit run -a flake8

- Running cdh cli:

      cdh <args>

(assuming the local development installation was used, see above)

## Releases

Changes should always be documented in [CHANGELOG.md](CHANGELOG.md).

### Releasing a new version
- Prepare pull-request to update [CHANGELOG.md](CHANGELOG.md) with the version number to release 
- Note *new*: In contrast to before, the package version will now be extracted from the git tag. 
  Whereas the [VERSION](VERSION) file will only be used for the automated update check.
  This means that one can choose to update the [VERSION](VERSION) file depending on whether 
  users should be notified of the new version automatically (or not).
- Have the pull-request approved and merged
- Create a tag with the new version number, e.g.:

      git tag 9.8.7
      git push origin 9.8.7

- Announce the new version in MS Teams channel "General", also citing the latest changes from changelog 
and instructions on how to upgrade. Example:

> **New Version of CDH CLI, v9.8.7**
>
> Added:
>  - Did some new stuff
>
> Changed:
>  - Change something as well
>
> Upgrade procedure:
>
>      pip install git+https://${USER}@atc.bmwgroup.net/bitbucket/scm/cdhx/cdh-cli.git@9.8.7
>
> For the full changelog, please see: https://atc.bmwgroup.net/bitbucket/projects/CDHX/repos/cdh-cli/browse/CHANGELOG.md
>

### Binary release (experimental)
[Pyinstaller](https://pyinstaller.readthedocs.io/en/stable/usage.html) is used to create binary executables. Executables for windows are only supported under windows as cross compilation is not supported by pyinstaller.
Two S3 buckets are named `cdh-authorization-asset-318780450878` (dev), `cdh-authorization-asset-402318116903` (prod) are available for the `cli_tooling` aws-profile (`account: 886227002799` , `friendly_name: BMW CDH-CLI Tooling`, `role: CDHX-DevOps`). The bucket `cdh-cli-bmw-artifact-repo` is available for development, but it does not have an interface thus its artifacts can not be accessed outside of AWS.
create_and_upload_executables is a python script provided that can be used to create executables for windows/mac. It accepts the following parameters:  
--release-version (--rv): cdh release version.  
--target-os: "mac" or "win".  
--current: optional flag, if set it replaces the current cdh version on the bucket.  
--prod/--dev: determines the destination bucket, default is --dev.  

Buckets endpoints are:  
dev: https://asset.iam-dev.data.bmw.cloud/cdh-cli/  
prod: https://asset.iam.data.bmw.cloud/cdh-cli/

#### create and upload binary executable  (Windows)
- Prerequisites:  
  - Access to the cli_tooling account (886227002799)

- If running on a native Windows machine:
  - Invoke `create_and_upload_executables.py --rv BINARY_VERSION_NUMBER --target-os win [--current]` using cli_tooling credentials, this will create a standalone executable (cdh.exe) with the specified BINARY_VERSION_NUMBER at `dist/cdh.exe`. It also uploads the created executable to `cdh-authorization-asset-318780450878` (dev bucket).

- If running on docker (recommended):
  - Run the script to create executables and upload to the S3 bucket, using cli_tooling credentials:
    ```
    docker run --rm -it -v "$PWD":/opt/cdh-cli -v "$HOME/.aws":/opt/wineprefix/drive_c/users/root/.aws tobix/pywine /opt/cdh-cli/bin/set_up_docker_container_then_create_and_upload_executables.sh --target-os win --current --prod --release-version x.y.z
    ```

#### create and upload binary executable  (MacOS)
Prerequisite:
  - Access to betalabs sandbox account (342962594065)
  - Access to the cli_tooling account (886227002799)
Actions:
  - In the betalabs sandbox console:
    - Allocate a dedicated host of instance family mac1 with instance type mac1.metal
    - Launch an EC2 instance from the cdh-cli-mac-template template, setting the host id to the id of the allocated host and using a new keypair. Use the MAC_TEST role as IAM role for this instance.
    - Allocate an elastic Public IP and associate it with the instance (might take some time until the instance is reachable under this address)  
  - Accept the fingerprint of the host
    ```
    ssh -i <keyfile> ec2-user@ec2-...eu-west-1.compute.amazonaws.com
    ```

  - Run the script with cli_tooling credentials:
    ```
    python create_and_upload_executables.py --target-os mac --current --rv x.y.z --ssh-key KEY.pem --ssh-user ec2-user --ssh-ip ec2-00-111-222-33.eu-west-1.compute.amazonaws.com --prod
    ```
  - Stop the instance again
  - After the host has been cleaned up: Release the dedicated host
  - Disassociate and release the Public IP