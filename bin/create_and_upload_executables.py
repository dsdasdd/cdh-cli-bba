#!/usr/bin/env python3
import logging
import os
import platform
import subprocess
from pathlib import Path

import boto3
import click
from mac_executables_creator import create_mac_release_in_temp_bucket

ARTIFACT_REPO_PROD_BUCKET_NAME = 'cdh-authorization-asset-402318116903'
ARTIFACT_REPO_DEV_BUCKET_NAME = "cdh-authorization-asset-318780450878"
EXECUTABLE_NAME_IN_REPO = 'cdh'
BINARY_VERSION_FILE = 'VERSION-BINARY'

LOG = logging.getLogger(__name__)

s3 = boto3.resource('s3')
s3client = s3.meta.client

current_folder_path = os.path.dirname(os.path.abspath(__file__))
dist_folder_path = os.path.join(current_folder_path, "..", "dist")


@click.command()
@click.option('--release-version', '--rv', required=True)
@click.option('--current', is_flag=True)
@click.option('--target-os', required=True, type=click.Choice(['win', 'mac'], case_sensitive=False))
@click.option('--ssh-key')
@click.option('--ssh-user')
@click.option('--ssh-ip')
@click.option('--prod/--dev', default=False)
def create_and_upload_binaries(release_version, current, target_os, ssh_key, ssh_user, ssh_ip, prod):
    if target_os == 'win':
        create_windows_executable(release_version)
    elif target_os == 'mac':
        if ssh_key and ssh_user and ssh_ip:
            create_mac_executables(release_version, ssh_key, ssh_user, ssh_ip)
        else:
            raise ValueError("ssh information are needed to create mac binaries")
    upload_to_artifact_repo(release_version, current, target_os, prod)

    if current:
        update_version_file_in_repo(release_version, prod)


def create_windows_executable(version):
    current_os = platform.system()

    if current_os != 'Windows':
        raise Exception(f'Can not run on {current_os}, windows binaries can only be created on windows')

    create_version_file_for_binaries(version)
    subprocess.run(f'pyinstaller --add-data "{BINARY_VERSION_FILE};." --onefile cdh.py --icon favicon.ico', check=True)


def create_mac_executables(version, ssh_key, ssh_user, ssh_ip):
    create_mac_release_in_temp_bucket(version, ssh_key, ssh_user, ssh_ip)
    s3client.download_file("cdh-cli-bmw-artifact-repo", f"mac_test/{version}/cdh", f"{dist_folder_path}/cdh")


def create_version_file_for_binaries(version):
    with open(BINARY_VERSION_FILE, 'w') as version_file_for_executable:
        version_file_for_executable.write(version)


def update_version_file_in_repo(release_version, is_prod):
    artifact_repo_bucket_name = ARTIFACT_REPO_PROD_BUCKET_NAME if is_prod else ARTIFACT_REPO_DEV_BUCKET_NAME
    print(f"updating version file in repository to {release_version}")
    s3client.put_object(Body=release_version, Bucket=artifact_repo_bucket_name, Key="cdh-cli/VERSION")


def upload_to_artifact_repo(release_version, is_current_version, target_os, is_prod):
    artifact_repo_bucket_name = ARTIFACT_REPO_PROD_BUCKET_NAME if is_prod else ARTIFACT_REPO_DEV_BUCKET_NAME

    os_extension = ".exe" if target_os == 'win' else ''

    executable_in_local_folder = f'{dist_folder_path}/cdh{os_extension}'

    executable_in_version_folder = f'cdh-cli/{release_version}/{EXECUTABLE_NAME_IN_REPO}{os_extension}'
    print(f"uploading {executable_in_local_folder} to version folder")
    s3client.upload_file(executable_in_local_folder, artifact_repo_bucket_name, executable_in_version_folder)

    if is_current_version:
        executable_in_current_folder = f'cdh-cli/{EXECUTABLE_NAME_IN_REPO}{os_extension}'
        print(f"uploading {executable_in_local_folder} to current version")
        s3client.upload_file(executable_in_local_folder, artifact_repo_bucket_name, executable_in_current_folder)


if __name__ == '__main__':
    os.chdir(Path(__file__).parent.parent)
    create_and_upload_binaries()
