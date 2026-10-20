# secretd (Rust)

secretd is a native local secret vault distributed as one executable. With no arguments it runs in
the system tray; its `get` command asks the desktop process for approval before releasing a secret.

This implementation is file- and protocol-compatible with the Deno implementation in
`../secretd`.

## Development

```sh
just check
just run
```

In another terminal:

```sh
target/release/secretd get service/account/token
```

Use `secretd --show` to launch the tray service with its window open. Desktop launches detach from
the invoking terminal; use `secretd desktop --foreground` when attached logs are useful for
development or diagnostics.

On macOS, build and install the single executable with:

```sh
just install
```

Tagged releases publish Linux x86-64 and macOS archives on the
[GitHub releases page](https://github.com/jpambrun/secretd/releases). The Linux build requires GTK 3,
Ayatana AppIndicator, xdo, Wayland, and XKB runtime libraries from the host distribution.

The vault uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and AES-256-GCM. Secret names and values
are encrypted together. Temporary grants and activity history exist only in memory.

By default the window follows the system light or dark appearance. Choose System, Light, or Dark
from the settings menu at the bottom of the sidebar. secretd saves the choice, and the page the main
window last showed, in `settings.json` next to the vault.

## AWS IAM Identity Center

secretd handles IAM Identity Center browser login with PKCE without invoking the AWS CLI or storing
SSO settings in `~/.aws/config`.

1. Open **AWS SSO**, enter the access portal URL and IAM Identity Center Region, then complete
   sign-in using your default browser on the same computer. The browser returns to a temporary local callback;
   there is no device code to enter. secretd discovers the AWS accounts and roles assigned to that
   identity.
2. Assign a local profile alias to each account you want to expose, and select the discovered roles
   secretd should offer as read-only and admin. Connection details, discovery results, mappings, and
   OIDC tokens are stored inside the encrypted vault.
3. Add only the non-sensitive credential helper entries to `~/.aws/config`, using those aliases:

```ini
[profile dev]
credential_process = /absolute/path/to/secretd aws credentials dev
region = ca-central-1

[profile staging]
credential_process = /absolute/path/to/secretd aws credentials staging
region = ca-central-1

[profile pre-prod]
credential_process = /absolute/path/to/secretd aws credentials pre-prod
region = ca-central-1

[profile prod]
credential_process = /absolute/path/to/secretd aws credentials prod
region = ca-central-1
```

4. Run tools normally. When a process asks for a configured profile, secretd opens a compact,
   independent approval window without taking keyboard focus. It lists every waiting request.
   The oldest is ticked and shows its verified process tree, so it can be denied or granted read-only
   or admin credentials. Tick several requests to answer them together; the tree then offers only
   the processes they all run under. A verified process that asks again while it waits is shown
   once and shares the answer.
   The window closes when nothing is waiting, and closing it denies the requests it shows, once.
   If the access token has expired, secretd renews it silently using its saved refresh token. Only
   when the session can no longer be renewed does it open your browser for sign-in, then resume the
   original credential request. **Refresh** and `secretd aws login` also reuse or renew the saved
   session before requesting browser sign-in, and rediscover the available accounts and roles.
   Network failures and temporary AWS errors preserve the saved session and report an error instead
   of starting a login.

The browser flow can reuse an existing browser sign-in when available. AWS or your identity provider
may still require authentication or consent when the underlying SSO session ends. Session duration
is controlled by your IAM Identity Center administrator.

This supports a saved-plan workflow without a caller-controlled access-level variable:

```sh
terraform plan -out=tfplan  # approve read-only credentials in secretd
terraform apply tfplan      # approve admin credentials in secretd
```

The selected role is pinned to the chosen process boundary and its children. New grants default to
30 minutes, can initially last at most 60 minutes, and can be extended in 15-minute increments from
the active-access screen (up to 60 minutes remaining). A later Terraform invocation does not reuse
the grant unless it is still a descendant of the selected live process boundary. Already-issued AWS
role credentials remain usable until their AWS-provided expiration time; revoking or expiring a
grant prevents secretd from issuing another set automatically. A denial is remembered for 30
minutes for the chosen process, its children and the profile; to stop a script that keeps retrying,
deny the script rather than one of its commands. An unanswered request blocks only the process that
asked and its children. A grant or denial also answers the waiting requests it covers. A request
whose process exits or is orphaned before it is answered, for example because a script's own timeout
killed it or the shell that ran it, is dropped without a denial. Active grants and remembered
denials appear under **Grants**, where they can be revoked or unblocked immediately.

On **Grants**, AWS access can be switched between read-only and admin without changing the process
boundary or expiration. The selected role applies to future credential requests. Credentials already
issued by AWS remain usable until their expiration.

Temporary secret grants also resolve pending requests for the same secret within the selected
process boundary. Allow once answers only the selected requests; closing the approval window
dismisses only the requests it displays.

The generic secret vault and `get` request remain compatible with the Deno implementation. Vaults
that contain the Rust application's AWS extension require an AWS-aware secretd version.
