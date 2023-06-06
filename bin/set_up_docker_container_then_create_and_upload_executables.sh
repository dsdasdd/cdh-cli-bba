#!/bin/bash

wine pip install --user -r opt/cdh-cli/requirements-dev.txt

export AWS_PROFILE=cli_tooling
wine python opt/cdh-cli/bin/create_and_upload_executables.py "$@"
