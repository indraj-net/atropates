# Atropates

A modern file encryption utility for UNIX systems.

## Prerequisites

If you wish to use the supplied Makefile as-is, you must have the following:

- a recent version of GCC
- GNU Make
- an x86-compatible CPU
- libsodium (+ development headers)

The Makefile contains some additional hardening options for ARM, but you must
enable these yourself.

Do not attempt to run this software on systems that do not implement POSIX, as
Atropates relies on defined system behaviour to enforce correctness properties.

## API stability

Interfaces do not change between revisions, but may change between versions.
Revisions which rectify security flaws are issued for the most recent version
and backported to the previous version (if necessary).
Earlier versions will not receive security fixes.

## Report a bug

To report a security bug, send me an email.
My contact details are available on my GitHub profile or via my
[website](https://indraj.net).
Please allow up to 48 hours for a reply, and up to 90 days for the issue to be
confirmed and fixed before disclosing it publicly.

For all other bugs, open an issue.

## Contributing

Thank you for your interest in contributing to Atropates!

Before submitting a PR, please open an issue to discuss your proposed changes.
All contributions are subject to the
[Developer Certificate of Origin (DCO)](https://developercertificate.org/).
By signing off on your commit(s), you are agreeing to be bound by the DCO.
Commits without sign-off will be rejected.
For the purposes of copyright provenance and transparency, you must use your
full, legal name and a non-temporary email address.

### Coding style

Please adhere to the kernel coding standards.
In particular:

- indent using tabs rather than spaces;
- indent width should be set to 8 chars; and
- line width should not exceed 80 chars unless this affects readability.

### Can I rewrite this in Rust?

Sure, but I will [reject](https://indraj.net/posts/rust) your PR.
You're welcome to maintain your own version, however.

## License

Atropates is licensed under the GNU Affero General Public License.
See COPYING.
