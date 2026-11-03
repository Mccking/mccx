#!/usr/bin/env python3
"""Patch mihomo's Android TUN so it can run as a normal (unprivileged) app.

The stock `android` build reads /data/system/packages.xml to build per-package
routing rules and aborts the whole TUN when that read fails. A full-device VPN
does not need those rules, so the patch logs and continues.

Applied by tools/build_mihomo.sh; exits non-zero if the patch site is missing,
which is the signal that upstream refactored the file.
"""

import pathlib
import sys

OLD = """\tpackageManager, err := getPackageManager()
\tif err != nil {
\t\treturn err
\t}
\ttunOptions.BuildAndroidRules(packageManager, l.handler)"""

NEW = """\tpackageManager, err := getPackageManager()
\tif err != nil {
\t\t// MccX: an unprivileged app cannot read /data/system/packages.xml, and a
\t\t// full-device tunnel does not need per-package rules.
\t\tlog.Warnln("MccX: android package rules unavailable: %v", err)
\t\treturn nil
\t}
\ttunOptions.BuildAndroidRules(packageManager, l.handler)"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_mihomo.py <server_android.go>", file=sys.stderr)
        return 2
    path = pathlib.Path(sys.argv[1])
    text = path.read_text(encoding="utf-8")
    if NEW in text:
        print(f"already patched: {path}")
        return 0
    if OLD not in text:
        print(f"patch site not found in {path} (upstream layout changed)", file=sys.stderr)
        return 1
    path.write_text(text.replace(OLD, NEW), encoding="utf-8")
    print(f"patched: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
