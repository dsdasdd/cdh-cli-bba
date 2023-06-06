# Changelog
All notable changes to this project will be documented in this file.

## unreleased
### Changed:
- Updated dependencies

## [5.2.0] - 2023-05-11
### Changed:
- Improved exception handling for corrupt cache
- Updated dependencies
- Added session scoped cache for jwt to avoid multiple jwt fetches if keyring is not available
- Fixed a bug where ``generate-config`` would generate the same config for bmw and bba
- Changed behaviour of ``generate-config`` if an error occurs when fetching the roles for one backend IDP. The config will now still be created containing all successfully received roles.

## [5.1.0] - 2023-01-17
### Changed:
- Use sts:TagSession for aws:RequestTag/Email on login by default, if rejected, use an untagged session.
- Restored compatibility with Python 3.7
- Updated dependencies
### Removed:
- Removed entrypoint ``awssso`` that is no longer used
 
## [5.0.0] - 2022-11-17
### Removed:
- legacy code handling options and configuration for old auth methods has been removed
- deprecated options ``--qnumber``, ``--pintype``, ``--cn``, ``--auth-method`` and ``--digital_id`` have been removed. 

## [4.6.0] - 2022-11-03
### Added:
- api scoped JWTs are now verified before returned, ensuring that no expired or otherwise invalid tokens are returned 
### Changed:
- Updated dependencies

## [4.5.0] - 2022-10-18
### Added
- Feature: Add new command ``cdh get-api-token`` to get an api scoped JWT
### Changed:
- Will now switch the ``--ignorekeyring`` option on by default for JWT storage if no keyring backend is available
- Restored compatibility with Python 3.7
- Updated dependencies

## [4.4.0] - 2022-08-22
### Added
- Feature: The temporary CDH credentials are now stored in the system keyring if available. 
Subsequent calls now do not require repeatedly giving consent via the browser.
### Changed
- ``awssso`` is now deprecated, all users of Public Cloud (FPC) managed roles are recommended to move to bmwaws-cli (see README.md)
- Removed erroneous position for option flag ``cdh list --loglvl=...``, as that never worked (use ``cdh --loglvl=... list`` to achieve the effect) 
- The backend IDP for cdh-auth will now be determined based on the identity, with ``--auth-idp`` setting the identity; This will enforce using the correct backend IDP in more scenarios than before.
- `cdh list` now outputs the roles sorted by account id

## [4.3.0] - 2022-06-02
### Added
- Feature: Add new option ``--auth-idp`` to specify which backend IDP should be used for authentication (CDHX-22260). 
- Feature: `cdh get-all` now performs sanity check for roles in config and comments roles that are no longer available.
- Guide users to create a config file if no config file is provided.
- Hide guest roles during automatic configuration generation.
### Changed
- Feature: Where applicable, commands now automatically detect the IDP from a config profile unless overwritten by ``--auth-idp`` (CDHX-22261)
- Fixed a bug where "cdh login" Opens approval twice for subroles with inaccessible parent role.

## [4.2.2] - 2022-05-24
### Changed
- Guest roles (which are technically required for CDH Data Portal) are no longer shown using `cdh list` (CDHX-20167).

## [4.2.1] - 2022-04-08
### Added
- Feature: Add command "cdh generate-config" to generate a config file.
### Changed
- Removed the need for BitBucket credentials (Q-Number) for version check.
- Profiles in config marked with "exclude-from-get-all" are not used for friendly names lookup.
- Fixed error "'type' object is not subscriptable" (CDHX-21217).

## [4.2.0] - 2022-03-22
### Added
- Feature: accelerate friendly name lookup for cdh and cdh list using local cache
### Changed
- Fixed a bug where calling cdh.exe login without parameters shows a stack trace.
- Improve error message for 403 (forbidden) in new auth method. 

## [4.1.1] - 2022-03-03
### Changed
- Fixed a bug where auth-method "direct-idp-auth" was not determined correctly (CDHX-20228)

## [4.1.0] - 2022-03-01
### Added
- Configure auth-stage for profiles in config.yml
- Opening webpages behaviour can be controlled using "browser-open-behaviour" in config file.
### Changed
- Fixed a bug: update bitbucket password with cdh-auth (for version check).
- Fixed a bug where command "cdh" without operation was not using the proper default auth-method (CDHX-20105)

## [4.0.2] - 2022-02-21
### Changed
- Fixed a bug where Firefox browser windows would not open when the executable is not on the path, e.g. on macOS (CDHX-19320)

## [4.0.1] - 2022-02-14
### Changed
- Revert awssso to use correct logic (as only direct-idp-auth supports it)

## [4.0.0] - 2022-02-14
### Changed
- Change default auth-method to "cdh-auth", "direct-idp-auth" is now deprecated. 

## [3.6.0] - 2022-02-01
### Added
- Feature: Add exclude-from-get-all flag for aws roles
- Feature: Add INT-Stage support for the new auth method (cdh-auth)
- Feature: Automatically open browser window for auth-method: cdh-auth
### Changed
- Changed logic for cdh-auth request ID
- Fixed a bug: override auth method using command line parameter

## [3.5.1] - 2021-10-27
### Changed
- Fixed a bug in CdhManager initialization if multiple identities are available

## [3.5.0] - 2021-10-25
### Added
- Always log version for debug loglevel
- Feature: Integrate new cli login into cdh-cli (Experimental)

## [3.4.1] - 2021-09-16
### Changed
- Fix installations problems due to the click dependency

## [3.4.0] - 2021-09-13
### Added
- Feature: Add experimental autocompletion for commands and profile names (supporting BASH and ZSH)

## [3.3.2] - 2021-08-16
### Changed
- Fallback to perform_two_step_sub_role_login() when federation endpoint doesnot return json
- Fix identityType detection for perform_two_step_sub_role_login()

## [3.3.1] - 2021-08-03
### Changed
- Fix incorrect AWS profile names (CDHX-14898)
- Fix "cdh login" for BBA profiles (CDHX-14932)

## [3.3.0] - 2021-07-26
### Changed
- Improved error message in case of unknown profiles. 
- Add support for BBA smscode
- Remove pinpoint 

## [3.2.2] - 2021-07-12
### Changed
- Bugfix for yubikey pins containing non digit characters

## [3.2.1] - 2021-07-02
### Changed
- Added correct default config behaviour for the cdh exec path

## [3.2.0] - 2021-06-30
### Added
- Support upcoming change in authorization interface

### Changed
- Removed support for PIN type "rsa" (as it is deprecated and will be removed on server-side soon)
- Fix session duration of 1 hour for roles assumed via role chaining
- Fixed a bug where `cdh login` incorrectly did not fetch new credentials
- Fixed a bug when comparing timestamps on Windows

## [3.1.0] - 2021-05-10
### Added
 - Warn if a password, PIN or HOTP input is too short (to detect problems when pasting from clipboard)
 - Flag ``--cn`` for ``awssso``. 

### Changed
 - Improve "newer version" notice to support versions installed from master without a version tag. 

## [3.0.0] - 2021-01-25
### Added
 - Automatic Migration of old config versions.

### Removed
- Support for old config versions has been removed.

### Changed
 - Readme only reflects new config version.

## [2.1.0] - 2021-01-18
### Added
 - Support for BBA ID with all commands (please see [README.md#Multi-Identity Support](README.md#multi-identity-support)) 
 - Add new config format v2 with support for BBA

### Changed
 - Fix error with account numbers getting parsed as octal values, which happens if they start with "0" 
 and only consist of digits "0" to "7". In case of ambiguity, an error will be raised with instructions
 on how to solve the problem. (CDHX-9656) 
 - Allow configuring Firefox installation by using `set-browser` together with `use-firefox-containers`

## [2.0.3] - 2020-12-02
### Changed
 - Prevent ReadTimeoutError on `cdh`, `cdh get`, `cdh list` if accounts in CN are available (CDHX-9468)
 - Prefer default region from `config.yml` when looking up friendly names

## [2.0.2] - 2020-12-02
### Changed
 - Do not throw an error and use first one in case of multiple matching roles (CDHX-9475)

## [2.0.1] - 2020-11-27
### Changed
 - Use authentication when reading account friendly names from Core API. 
   Please note that this will make `cdh list` and `cdh get` (without profile) slower, 
   but authentication was now made mandatory.
   (Earlier versions of CDH CLI will no longer be able to resolve account friendly names!)
 - Fix pinpoint warning due to missing friendly name (CDHX-8744)

## [2.0.0] - 2020-10-29
### Added
 - Option ``-output-credentials`` to visibly output credentials

### Changed
 - Versions for third party dependency packages are now fixed
 - Credentials will no longer be logged to log files
 - Credentials will no longer be output unless option `--output-credentials` is given
 - Only check for new versions once every 12h (or with `--version`)
 - Failing commands will now set a non-zero exit code
 - Network timeouts are reduced
 - De-facto minimum version Python 3.7 is now set explicitly

## [1.3.1] - 2020-10-02
### Changed
 - Now integrates and makes `awssso` commands available, too. 

## [1.3.0] - 2020-08-12
### Changed
 - Login with subroles now directly returns the federation url if possible

## [1.2.0] - 2020-07-27
### Added
 - Supports login to China AWS partition

## [1.1] - 2020-06-04
### Added
 - `cdh login` now works with sub-roles
 
### Changed
 - the "doAuthentication.do" url now gets determined dynamically
 
## [1.1.1] - 2020-06-22
### Changed
 - HOTFIX duplicates in saml response no longer appear in `cdh list`
 
## [1.1.2] - 2020-06-25
### Changed
 - now fetches credentials for the FG-25 sso role for 12 hours by default
 
## [1.2.0] - 2020-07-07
### Added
 - added logging to the CDH CLI
 - `cdh --version` returns installed version now
 - every time the cdh is used, it tries to check if there is a newer version
 - added click-spinner and a progress bar
 - Coloring of tabs in FF is enabled
 - Added support for china roles
### Changed
 - saml roles are now sorted
 - `cdh get-all` now fetches all user profiles
