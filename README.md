Up-to-date docs: https://data.bmw.cloud/docs/getting_started/x_0_cdh_cli.html .
Frequently asked questions: [Questions](https://atc.bmwgroup.net/confluence/questions/topics/1190035861/cdh-cli)

## Cloud Data Hub CDH CLI

The Python-based command-line interface (CLI) helps to
* select a suitable account/environment from the CDH,
* generate and persist AWS credentials via Security Token Service (i.e. `access_key`, `secret_key`, `security_token`), and
* generate login links to the AWS Management Console.

### Important Notice: Access to Public Cloud (FPC) roles

AWS account roles that are _not_ managed via CDH Data Portal or CDH ADGR, but instead via Public Cloud (FPC), must be handled using [bmwaws-cli](https://developer.bmw.com/docs/public-cloud-platform-aws/2_developyourapplication/gettingstarted/cli/cli/#bmwaws-cli).

Example: all roles named "role/fpc/UserFull", or if your role is called "sso"

The usage of CDH CLI for Public Cloud based roles is *not possible*.

## Installation

### python version
Prerequisite: Python 3.7 or newer + Pip

```bash
pip install git+https://${USER}@atc.bmwgroup.net/bitbucket/scm/cdhx/cdh-cli.git
```

or, if you want to install a specific version (e.g. 5.2.0):

```bash
pip install git+https://${USER}@atc.bmwgroup.net/bitbucket/scm/cdhx/cdh-cli.git@5.2.0
```

### precompiled binaries (standalone)
Precompiled binaries can be downloaded from the following URLs. The URLs are only accessible from BMW network IPs.  
For Windows: https://asset.iam.data.bmw.cloud/cdh-cli/cdh.exe  
For Mac: https://asset.iam.data.bmw.cloud/cdh-cli/cdh  

or, if you want to install a specific version (e.g. 5.2.0):
For Windows: https://asset.iam.data.bmw.cloud/cdh-cli/5.2.0/cdh.exe  
For Mac: https://asset.iam.data.bmw.cloud/cdh-cli/5.2.0/cdh  

## First steps 
The following command: 
```bash
cdh generate-config
```
initiates a login at the CDH and creates an initial configuration file. The created file contains basic config information for all the directly accessible roles.
This will check all backend logins, i.e. both BMW and BBA, so you will be prompted to log in to both. If you wish to use only one login, ignore the other one
and either decline the CLI approval after login or wait for 60 seconds. The config will only contain the roles assumable using the logins that were successful 
during config generation.

## Usage

This CLI, which is available via `cdh` offers nine commands : `get`, `get-all`, `list`, `login`, `exec` `generate-config`, `open_config`, `clear-cdh-keyring` and `get-api-token`. 

1. The command `get` can be called with an optional argument specifying the target role for which you wish to acquire credentials. This role is specified in the format `${ROLE_NAME}_${ACCOUNT_ID}` (or `${ROLE_NAME}_${ACCOUNT_ID}_bba` for BBA roles, see [Multi-Identity Support](#multi-identity-support)).
You will be redirected to the CDH login page and subsequently asked for consent to export the CDH credentials to the cli. Login is skipped if you are already logged in with the correct organization.
If no argument is given, you will be presented a list of all roles available to you, and then prompted to choose a role from this list.
Subsequently, temporary credentials are gathered and stored in your AWS credentials file (~/.aws/credentials).
2. `get-all` works like `get` but persists temporary credentials for all of your available roles at the same time. 
3. The command `list` prints out a list of all roles available to you. 
4. The command `login` can be called with an optional argument specifying the target role for the login. This role is specified in the format `${ROLE_NAME}_${ACCOUNT_ID}`.
If no argument is given, an attempt will be made to retrieve the target role from the environment variable `AWS_PROFILE`.
If your AWS Credentials file contains valid credentials for the requested role, a browser window opens up which logs you into the AWS console.
Otherwise, a `get` request will be executed first, prompting you to authenticate. 
5. The `exec` command is similar to `aws-vault exec`. It works only with pre-configured profiles in `~/.config/cdh/config.yml` described below.
If there are valid credentials for the given profile, `cdh` will execute the command by setting the `AWS_PROFILE` environment variable.
Use it as follows
```bash
cdh exec some-profile -- aws s3 ls
```
6. The `generate-config` command creates a new `config.yml` file with the accounts and roles of your CDH user.
7. The `open_config` command will open the currently used configuration file, if any.
8. The `clear-cdh-keyring` command will remove all cached temporary CDH credentials from the keyring. This does not affect aws credentials. 
9. The `get-api-token` command will get and print out an api scoped JWT in the format `$jwt_name=$jwt_value`. You will be redirected to the CDH login page 
and subsequently asked for consent to export the CDH credentials to the cli. Login is skipped if you are already logged in with the correct organization.

Once you have retrieved valid credentials, you can set the environment variable `AWS_PROFILE` to execute AWS CLI commands with the respective role.
By running `cdh get` repeatedly, you may store credentials for several roles, so that you can easily switch between them by simply changing `AWS_PROFILE`.

Unless the `--ignorekeyring` option is given, the CDH credentials for each used organization will be stored in the keyring.
Future calls then do not require explicit login/consent until expiry of the credentials (up to 12 hours).

### Multi-Identity Support

The identities supported by the CDH CLI directly correspond with the organizations used by the CDH login:
* BMW ID is the identity used for login via the "BMW Group" organization
* BBA ID is the identity used for login via the "BMW Brilliance Automotive " organization

Which identity will be used depends on the command and the context.
* Any identity explicitly given with the `--auth-idp` option takes precedence.
* `cdh list`, `cdh get-all` will use all identities where:
  * the identity is configured in the configuration file (see below)  
    (unless `disable-by-default` is set)
* `cdh get <target>`/`cdh login <target>` will use the identity associated with `<target>`
* `cdh`/`cdh get`/`cdh login` (without target) will check which identities can be used as for `cdh list`, and:
  * if only one identity is enabled, it will be used
* If no config is present and no options are given, the identity used by your currently active CDH session is used. 
* If you are currently not logged in to the CDH either, you will be requested to select an organization, which implies an identity selection as stated above.  

### Configuration file

For a more comfortable usage, we advise the use of a configuration file. This is a yaml file located in `~/.config/cdh/config.yml` that follows the structure of the example below:
You can create and open the file with `cdh open_config`.

#### Current Config Format (v2)

```yaml
loglvl: warning
version: v2

identities:
  bmw:
    region: eu-west-1
    aws-profiles:
      developer:
        account: 123456789012
        role: CDH-Developer
        region: us-east-1
      devops1:
        account: 123456789012
        role: CDHX-DevOps
      china-data-engineer:
        account: 423028235348
        role: CDHDataEngineer
      dev-ops-us:
        account: 987654321098
        role: CDHX-DevOps
        region: us-east-1
      dev-ops-eu:
        account: 987654321098
        role: CDHX-DevOps
        region: eu-central-1
      test-slave-role:
        account: 987654321098
        role: CDHX-DevOps
        session_length: 15
      with-leading-zeros:
        account: "012345678901"
        role: CDHX-DevOps
      using-subrole:
        account: 111111111111
        role: directly-assumed-role
        subrole: arn:aws:iam::555555555555:role/role-assumable-from-directly-assumed-role
  bba:
    region: cn-north-1
    aws-profiles:
      bba_test_provider:
        account: 114925441656
        role: CDHX-CDHDataEngineer 
```

The identities section currently supports the following types (also see "Multi-Identity Support" above): 
- `bmw` for "BMW ID"
- `bba` for "BBA ID"

Most users will be using only one identity here. (The other one can be left out then.)  
However, please note that certain features (e.g. automated cli version check) will only work with a BMW ID.

Profile names need to be unique across all identities (as they will be used as AWS profile names).

In the example above, '123456789012' and '987654321098' are the account IDs where the user has access to the specified roles.
The names 'developer', 'devops1', 'devops2', 'dev-ops-us' and 'dev-ops-eu' are chosen by the user and serve as aliases for the respective roles.
For example, executing `cdh get developer` will then fetch the credentials for the role 'CDH-Developer' in '123456789012' and store them under 'developer' in your AWS credentials file, so you use `AWS_PROFILE=developer` afterwards.
In the case of the role 'CDH-Developer' the specified region is 'us-east-1', while for 'CDHX-DevOps' the users default region 'eu-west-1' is used.
<br> The Profile 'test-slave-role' first fetches credentials for 'CDHX-DevOps', then uses them to assume 'cdh-core-functional-tests-master' in the same account. You can also specify a custom session length in minutes.
If you want to assume a role in another account use an ARN instead of a name.

You can also assume a role (called "subrole" here) via another role.
Due to AWS limitations the session length will be limited to 1 hour then.

'114925441656' is an account ID where the user, using BBA authentication, has access.   
The same structure and options are available as under 'bmw', with the exception that second factor authentication
is not yet supported for 'bba' identity.

##### Work with BBA ID only

For work with BBA ID only, it is recommended to at least use the following minimal configuration so that the correct region
will be used (this also enables BBA ID instead of BMW ID, which would be enabled by default otherwise):
```yaml
identities:
  bba:
    region: cn-north-1
```

##### Exclude certain profile from get-all

To exclude a config profile from `get-all`, the `exclude-from-get-all` flag can be used. For example:
```yaml
excluded-from-get-all-profile:
  account: "012345678901"
  role: CDHX-DevOps
  exclude-from-get-all: true
```
Profiles excluded from `get-all` can still be used by other commands like `get` or `login` that take the profile name as an argument.

##### Additional Features

One can disable an identity unless it is specifically activated (by target profile or by command line options specific to that identity)
with `disable-by-default: True`, so that e.g. `cdh list` will only consider the other identities by default:
```yaml
identities:
  bmw:
    # ... some settings
  bba:
    disable-by-default: True
```

## Example Usage

Assuming you have the above `config.yml` file, a possible terminal session could look like the following

```bash
$ cdh list                       # Lists all eligible roles
$ cdh get devops1                # The temporary credentials are obtained and stored under the profile name devops1 in ~/.aws/credentials
$ AWS_PROFILE=devops1 aws s3 ls  # Lists all S3 buckets using the temp. credentials of devops1
$ export AWS_PROFILE=devops1     # Sets the default AWS profile to devops1. All commands from here on will user the devops1 profile
$ aws s3 ...
$ terraform apply
$ # Do other things as devops1
$ cdh get devops2                # The temporary credentials are obtained and stored under the profile name devops2 in ~/.aws/credentials
$ AWS_PROFILE=devops2 aws s3 ls  # Temporarily switch to devops2 and lists all S3 buckets. The default AWS profile devops1 is overridden.
$ cdh exec devops3 -- aws s3 ls  # Execute "aws s3 ls" using the profile devops3.
$ cdh login devops1              # Opens the AWS management console as devops1 without fetching new credentials.
$ # Do other things
```

## Tips and Tricks

### Current Profile in the Shell Prompt

By adding `$(echo $AWS_PROFILE)` to the `PROMPT` environment variable, you can display the currently set `AWS_PROFILE` in the shell prompt.
For example

```bash
PROMPT='... YOUR EXISTING PROMPT SETTINGS ... $(echo $AWS_PROFILE) ... FURTHER EXISTING SETTINGS ...'
```

### Bash Function to Set the Environment Variable

By adding a function to `~/.bashrc`, you can set the `AWS_PROFILE` environment variable for the current shell.
For example, having the following in your `~/.bashrc`

```bash
role () {
    export AWS_PROFILE=$1
}
```

will enable you to perform the switch to the role `devops2` as follows

```bash
$ role devops2
```

### Open AWS Management Console in dedicated Firefox containers

In order to work with multiple accounts at the same time, you can use Firefox containers.
They allow you to be logged into different accounts in separate tabs at the same time.

To use this feature in CDH CLI, first install the [Open external links in a container](https://addons.mozilla.org/en-US/firefox/addon/open-url-in-container/) add-on.
Then activate in _~/.config/cdh/config.yml_:

```yaml
use-firefox-containers: true
set-browser: "/mnt/c/Program Files/Mozilla Firefox/firefox.exe"  # Optional: Full path to a non-standard Firefox installation you want to use (e.g. Firefox installed on Windows when working on WSL)
```

The created containers will be called like the aliases set in this config file.
If you want to customize the colors and icons for these containers, you can use the [Multi-Account Containers](https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/) add-on.

If this plugin is used, the CDH CLI will try to seperate containers by colors and icons. If you used this plugin before
color and icon functionallity was built in, containers will stay on their old setting. To reset these color and icon
settings go to Preferences --> Tabs --> (In the row of 'Enable Container tabs') Settings --> Remove all old
tab-settings here.

You can specify the path to a custom firefox installation by using `set-browser` in your configuration. This is usually not necessary, but useful e.g. if you are working on WSL. As a precaution, the value of `set-browser` is only used if it contains the substring `firefox`.

### Open multiple AWS Management Consoles by using dedicated chrome profiles

If you want to work simultaneously with multiple aws accounts without having to logout and login on access,
you can use chrome-profiles to enable dedicated chrome-windows for each of your defined AWS_PROFILE.
Be aware that due to limitations in chrome, chrome-profiles do not share browser data like bookmarks, cookies and so on.
To reduce trouble you have the option to choose one AWS_PROFILE (called "default") which will have access
to your browser's data like bookmarks and so on.

To use this feature in CDH CLI, configure _~/.config/cdh/config.yml_:

```yaml
use-chrome-multiple-windows: true|false # Required
use-chrome-multiple-windows-default: "cdh-dev" # Optional: An AWS_PROFILE which should be able to access your browser's default data.
set-browser: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"  # Required: Full path to executable which is to be used as browser.
```

###  Changing the browser behavior when opening web pages
It is possible to configure the browser behaviour for opening webpages using `browser-open-behaviour` in config.yml:
```yaml
browser-open-behaviour: default|window|tab
```
where `window` tries to open requested URLs always in a new window, and `tab` tries to open them in a new tab. Please notice that this behaviour is not enforced and varies depending on the operating system and browser used. 

### Working with Windows and WSL

On Windows, the [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/) is a very good option for using command line tools geared towards linux and/or macOS. Here are some tips for using the cdh cli with WSL:
- **Keyring:** WSL uses the [keyring](https://pypi.org/project/keyring/) python package, which offers an interface to password managers. However, the natively supported backends don't work with WSL. Users will need to install their own backend.\
A simple solution that works fine is [pass](https://www.passwordstore.org/), a minimalistic GPG-based unix password manager. The corresponding keyring backend can be found here: [keyring-pass](https://pypi.org/project/keyring-pass/) 
  - Install pass
  - Install keyring-pass using a python package manager
  - Configure pass to use the keyring backend (this can be done using the `set_keyring` method, see the keyring documentation)
- **Firefox path:** To use a browser installed on Windows, you will need to specify the full path to the browser executable in the `set-browser` configuration. For example:
```yaml
set-browser: "/mnt/c/Program Files/Mozilla Firefox/firefox.exe"
```

### Disabling Keyring

The CDH CLI will store your temporary CDH credentials in the system keyring if available. When using the legacy option `--auth-method direct-idp-auth`, passwords will also be stored in the keyring.
The `clear-cdh-keyring` command deletes all stored cdh credentials (but not passwords). 

If you don't wish to use your keyring with `cdh-cli`, you can disable it by setting `use-keyring: false` in your `config.yml` or use the `--ignorekeyring` option.

### Enable Autocomplete for Commands and Profile Names

`cdh-cli` supports autocomplete for its commands and for the names of profiles stored in the config file. However, not all shells offer support for auto-completion. This feature is supported for Bash (>=4.4.0) and Zsh.

To enable autocomplete, the following line should be called at each bash start

```sh
eval "$(_CDH_COMPLETE=bash_source cdh)"
``` 

This can also be done automatically by adding the previous command to the `~/.bashrc` file.

For **ZSH** the following command can be used, it can also be added to `~/.zshrc`

```sh
eval "$(_CDH_COMPLETE=zsh_source cdh)"
```


If `cdh-cli` is not installed globally and used inside a virtual environment, then the command for **bash** should be changed into:

```sh
eval "$(_CDH_COMPLETE=bash_source PATH_TO_CDH_INSIDE_VIRTUAL_ENV)"
```

**ZSH**:

```sh
eval "$(_CDH_COMPLETE=zsh_source PATH_TO_CDH_INSIDE_VIRTUAL_ENV)"
```

Whereas PATH_TO_CDH_INSIDE_VIRTUAL_ENV can be found by executing the following command:

```sh
which cdh
```

### Setting stage for cdh-auth
Authentication process using cdh-auth can be performed on two different stages (int or prod). If not specified, prod is used as the default auth-method-stage.  
It is possible to specify one stage to use with cdh-auth. This can be done either using parameter: ```--auth-method-stage=int```, or by adding ```auth-method-stage: int``` to profile's config. For example:
```yaml
int-stage-profile:
  account: "012345678901"
  role: CDHX-DevOps
  auth-method-stage: int
prod-stage-profile:
  account: "109876543210"
  role: CDHX-DevOps
```
Also, it is possible to override the ```auth-method-stage``` given in config using the ```--auth-method-stage``` parameter.

###  Perform sanity check for roles in config
The ```get-all``` command automatically comments out roles that can not be assumed inside the config file. This can be turned off using ```--disable-sanity-check``` or by setting ```sanity-check: False``` in config file.
