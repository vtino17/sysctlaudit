# sysctlaudit

Check sysctl configuration against a kernel-hardening baseline.

Servers set kernel security knobs in `/etc/sysctl.conf` and `/etc/sysctl.d/*.conf`
and then nobody looks at them again. sysctlaudit reads those files (or any file
you point it at), compares each setting to a CIS-style baseline, and reports what
is wrong or missing — with a 0-100 hardening score. It is the audit counterpart
to whatever *applies* the hardening.

It is a single Python file with no dependencies, reads files only, and exits
non-zero on any HIGH finding or wrong value — so it fits CI or a nightly check.

## Usage

```sh
sysctlaudit                       # /etc/sysctl.conf + /etc/sysctl.d/*.conf
sysctlaudit ./99-hardening.conf   # a specific file
sysctlaudit /etc/sysctl.d         # a directory of .conf files
```

Example:

```
$ sysctlaudit ./sysctl.conf
== sysctl (1 file(s)) ==
  HIGH    net.ipv4.tcp_syncookies: is 0, should be 1 (SYN-flood protection)
  MEDIUM  kernel.dmesg_restrict: not set - relies on the kernel default (restrict dmesg to root)
  LOW     net.ipv4.ip_forward: IP forwarding is on - correct only if this host is a router/NAT/VPN
  hardening score: 71/100 (partial) - 17 baseline keys
```

## What it checks

The baseline covers the well-known hardening knobs: `tcp_syncookies`,
reverse-path filtering, ICMP redirect accept/send, source routing (v4 and v6),
`log_martians`, broadcast-ping ignore, `randomize_va_space` (full ASLR),
`kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `sysrq`,
`fs.protected_hardlinks`/`protected_symlinks`, and `fs.suid_dumpable`.

It understands "at least" knobs (`kptr_restrict=2` satisfies `>= 1`), merges
multiple files with the later one winning — the way `sysctl.d` precedence works —
and treats `ip_forward` as context-dependent (a note, not a failure, since
routers need it).

## Caveat

This audits the *configuration files*. It does not read the running kernel
(`sysctl -a`) — a value can be set at runtime without being in a file, or be in a
file that has not been applied. Pair it with `sysctl --system` on the host. A
setting flagged here may also be intentional for your role (a router needs
`ip_forward`).

## Tests

```sh
./tests/run.sh
```

Builds hardened, weak and split-across-files fixtures in a temp dir and asserts
the findings, the score, the `>=` comparator and the later-file-wins merge.

## License

MIT. See `LICENSE`.
