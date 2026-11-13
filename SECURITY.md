# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue or pull request:
open the [Security tab](https://github.com/GeorgiosDelkos/vigil/security) and choose
**Report a vulnerability**. Only the maintainer can read the report.

Include what you found, the version or commit, and the steps or a proof of concept that show it.
You will get a reply in the advisory thread. A fix ships in a new release, and the advisory is
published with credit to you unless you ask otherwise.

## Supported versions

Only the latest release gets security fixes. The app checks for new releases every 12 hours and
offers to install them.

## In scope

- The menu-bar app and the `vigil` CLI, including what they let a coding agent do during a sweep
  or a fix.
- How the app reads and stores data on your Mac, and what it sends over the network.
- The update channel: release signing, the update signature check and the release workflow.

Vulnerabilities in the advisories Vigil reports (a CVE in software you have installed) belong to
that software's maintainers, not here.
