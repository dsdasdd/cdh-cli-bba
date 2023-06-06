import os
import subprocess
from pathlib import Path

import boto3


def create_mac_release_in_temp_bucket(release_version, ssh_key, ssh_user, ssh_ip):
    current_folder_path = os.path.dirname(os.path.abspath(__file__))
    dist_folder_path = os.path.join(current_folder_path, "..", "dist")

    temp_zip_file_path = f"{dist_folder_path}/cdh-cli-master.zip"
    subprocess.run(["git", "archive", "--format", "zip", "--output", temp_zip_file_path, "master"], check=True)

    s3 = boto3.resource('s3')
    s3client = s3.meta.client
    s3client.upload_file(temp_zip_file_path, "cdh-cli-bmw-artifact-repo", "mac_test/cdh-cli.zip")

    run_via_ssh_command = ["ssh", "-i", ssh_key, f"{ssh_user}@{ssh_ip}"]

    def _run_via_ssh(command_and_args):
        subprocess.run(run_via_ssh_command + command_and_args, check=True)

    try:
        _run_via_ssh(["/usr/local/bin/aws", "s3", "cp", "s3://cdh-cli-bmw-artifact-repo/mac_test/cdh-cli.zip cdh-cli.zip"])
        _run_via_ssh(["unzip", "cdh-cli", "-d", "cdh-cli/"])
        _run_via_ssh(["echo", release_version, ">", "cdh-cli/VERSION-BINARY"])
        _run_via_ssh(["cdh-cli/bin/reset_python_environment.sh"])
        _run_via_ssh(["-t", "cd", "cdh-cli", "&&", "/usr/local/bin/python3", "-m", "PyInstaller", "--add-data", "VERSION-BINARY:.", "--onefile", "cdh.py", "--icon", "favicon.ico"])
        _run_via_ssh(["/usr/local/bin/aws", "s3", "cp", "--acl", "bucket-owner-full-control", "cdh-cli/dist/cdh", f"s3://cdh-cli-bmw-artifact-repo/mac_test/{release_version}/cdh"])
        _run_via_ssh(["rm", "-r", "cdh-cli", "&&", "rm", "cdh-cli.zip"])
    finally:
        Path(temp_zip_file_path).unlink()
