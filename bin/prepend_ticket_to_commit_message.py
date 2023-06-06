#!/usr/bin/env python3
import re
import subprocess
import sys


def git_current_branch():
    return subprocess.check_output(["git rev-parse --abbrev-ref HEAD"], shell=True).decode().strip()


TICKET_REGEX = r"[A-Z]{3,}-[0-9]+"


def print_local(x, **kwargs):
    print(f"[Jira prefix hook] {x}", **kwargs)


def extract_ticket(input):
    ticket = re.search(TICKET_REGEX, input)
    return ticket.group(0) if ticket else None


def starts_with_ticket(commit_message):
    ticket = re.search(f"^{TICKET_REGEX}", commit_message)
    return ticket.group(0) if ticket else None


def skip_because_of_commit_message(old_commit_message, branch_ticket):
    existing_ticket = extract_ticket(old_commit_message)
    if existing_ticket == branch_ticket:
        print_local(f"Commit message already prefixed with current branch’s ticket {existing_ticket}")
    else:
        print_local(
            f"Commit message already prefixed with ticket {existing_ticket} - skip prepending branch-based ticket ({branch_ticket})"
        )


def prepend_branch_ticket(commit_message_file, old_commit_message, branch_ticket, current_branch):
    print_local(f"Prepending Jira ticket ID from current branch: {current_branch}")
    new_commit_message = f"{branch_ticket} {old_commit_message}"
    open(commit_message_file, "w").write(new_commit_message)


def edit_commit_message(commit_message_file):
    old_commit_message = open(commit_message_file, "r").read()
    current_branch = git_current_branch()
    branch_ticket = extract_ticket(current_branch)
    if branch_ticket and starts_with_ticket(old_commit_message):
        skip_because_of_commit_message(old_commit_message, branch_ticket)
    elif branch_ticket:
        prepend_branch_ticket(commit_message_file, old_commit_message, branch_ticket, current_branch)


def main():
    if len(sys.argv) < 2:
        print_local("Expecting at least one argument (filename of the commit message)")
        sys.exit(1)
    edit_commit_message(commit_message_file=sys.argv[1])


if __name__ == "__main__":
    main()
