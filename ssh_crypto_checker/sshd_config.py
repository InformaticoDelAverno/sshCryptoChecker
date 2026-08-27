"""Authenticated audit of a server's effective SSH configuration.

Most real misconfigurations are invisible from outside: PermitRootLogin,
password authentication, forwarding, MaxAuthTries. Reading them requires
logging in, which is why this is separate from the rest of the tool and needs
credentials.

Two decisions shape the module.

**It reads ``sshd -T``, not the file.** ``sshd -T`` prints the configuration
sshd actually resolved: ``Include`` directives are followed, defaults are
filled in, and the values are normalised. Parsing ``/etc/ssh/sshd_config``
directly gives a confident and sometimes wrong answer, because since OpenSSH
8.2 the configuration is routinely split across ``sshd_config.d`` and because
an unset directive still has a default that matters.

**It delegates the connection to the system ``ssh`` client.** Implementing
authenticated SSH here would mean Ed25519 and RSA signing, OpenSSH private key
parsing and bcrypt-pbkdf for encrypted keys: a great deal of cryptographic code
to reimplement something already present on every machine that would run this,
and already integrated with agents, ``~/.ssh/config`` and known_hosts.

``sshd -T`` needs to read the host keys, so the account needs to be root or
have passwordless sudo for it. Both are attempted, and the failure says which.
"""

from __future__ import annotations

import base64
import binascii
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .models import (
    AccountKeys,
    AuthorizedKeyEntry,
    Credentials,
    EffectiveConfig,
    FileMode,
    MatchContext,
    ModuliFile,
    PackageInfo,
    UserPrivateKey,
)
from .ssh_protocol import parse_host_key_blob, printable

__all__ = ["REMOTE_SCRIPT", "fetch_effective_config", "parse_effective_config", "parse_file_modes"]

_SECTION = "###SSHCC:"

#: Run on the target. Deliberately POSIX sh, since a hardened host may have no
#: bash, and deliberately one round trip.
REMOTE_SCRIPT = r"""
emit() { printf '%s%s###\n' "###SSHCC:" "$1"; }

# stat -c is GNU and busybox; -f is BSD. Same field order either way, and the
# path is last on purpose: a file name may contain a space, and everything
# that reads these lines splits them on whitespace. With the path in the
# middle every column after it shifted, which silently attributed one key's
# permissions to another key -- and stopped saying that an unprotected
# private key was unprotected.
statline() {
    stat -c '%a %U %G %n' "$1" 2>/dev/null && return 0
    stat -f '%Lp %Su %Sg %N' "$1" 2>/dev/null && return 0
    return 1
}

CONFIG_TEXT=""
for candidate in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd sshd; do
    if [ -x "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
        CONFIG_TEXT=$("$candidate" -T 2>/dev/null) && [ -n "$CONFIG_TEXT" ] && break
        CONFIG_TEXT=$(sudo -n "$candidate" -T 2>/dev/null) && [ -n "$CONFIG_TEXT" ] && break
        CONFIG_TEXT=""
    fi
done

emit SSHD-T
if [ -n "$CONFIG_TEXT" ]; then
    printf '%s\n' "$CONFIG_TEXT"
else
    echo "SSHCC-ERROR: could not run 'sshd -T'; the account needs root or passwordless sudo for it"
fi

emit MATCH-BLOCKS
grep -iE '^[[:space:]]*(Match|Include)[[:space:]]' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true

emit FILES
# The host key paths come from the configuration itself rather than a guess at
# /etc/ssh, because a server may keep them anywhere.
printf '%s\n' "$CONFIG_TEXT" | while read -r name value rest; do
    case "$name" in
        hostkey|hostcertificate|authorizedkeysfile|trustedusercakeys|revokedkeys)
            [ -e "$value" ] && statline "$value"
            [ -e "${value}.pub" ] && statline "${value}.pub"
            ;;
    esac
done
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d; do
    [ -e "$f" ] && statline "$f"
done

emit AUTHORIZED-KEYS
# AuthorizedKeysFile is configurable and frequently configured -- to
# /etc/ssh/authorized_keys/%u on hosts that keep the files out of the users'
# reach, for instance -- so the path is read from the configuration instead of
# assumed. sshd expands %h and %d to the home directory, %u to the user name
# and %% to a percent sign, and treats a relative path as relative to home.
AK_PATHS=$(printf '%s\n' "$CONFIG_TEXT" | awk '$1=="authorizedkeysfile"{$1=""; print}')
[ -z "$AK_PATHS" ] && AK_PATHS=".ssh/authorized_keys .ssh/authorized_keys2"
WHO=$(id -un 2>/dev/null || echo "$USER")
# Unquoted on purpose: sshd separates several paths with spaces.
for f in $AK_PATHS; do
    f=$(printf '%s' "$f" | sed -e "s|%h|$HOME|g" -e "s|%d|$HOME|g" -e "s|%u|$WHO|g" -e 's|%%|%|g')
    case "$f" in
        /*) ;;
        *) f="$HOME/$f" ;;
    esac
    if [ -e "$f" ]; then
        printf 'MODE '; statline "$f"
        cat "$f" 2>/dev/null
    fi
done

emit MATCH-RESOLVED
# 'sshd -T' with no connection context reports the global configuration only,
# so a Match block that relaxes something for one group is invisible in it.
# 'sshd -T -C' takes a context and resolves the blocks, which is the only way
# to see what a particular connection would actually be given.
#
# The context has to be built from each block's own criteria: a block matching
# 'User deploy' is only visible to a probe claiming to be deploy. What cannot
# be built is reported as still needing a human, rather than skipped silently.

# Only the criteria sshd -C understands. Group is resolved to a member,
# because -C takes a user and sshd derives the groups itself.
match_lines() {
    grep -hiE '^[[:space:]]*Match[[:space:]]' \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
}

first_member() {
    members=$(getent group "$1" 2>/dev/null | awk -F: '{print $4}' | cut -d, -f1)
    if [ -n "$members" ]; then
        echo "$members"
        return 0
    fi
    # No secondary members: look for an account whose primary group it is.
    gid=$(getent group "$1" 2>/dev/null | awk -F: '{print $3}')
    [ -z "$gid" ] && return 1
    getent passwd 2>/dev/null | awk -F: -v g="$gid" '$4 == g { print $1; exit }'
}

match_lines | while IFS= read -r line; do
    # Everything after the word Match, as criterion/value pairs.
    rest=$(printf '%s' "$line" \
        | sed -e 's/^[[:space:]]*//' -e 's/^[Mm][Aa][Tt][Cc][Hh][[:space:]]*//')
    case "$rest" in
        *!*)
            echo "MANUAL $line"
            echo "REASON the criteria are negated, so no single context represents them"
            continue
            ;;
        [Aa][Ll][Ll]*)
            echo "MANUAL $line"
            echo "REASON 'Match all' applies to every connection already"
            continue
            ;;
    esac

    ctx_user=""; ctx_addr=""; ctx_host=""; ctx_lport=""; unsupported=""
    set -- $rest
    while [ $# -ge 2 ]; do
        criterion=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
        value=$(printf '%s' "$2" | cut -d, -f1)
        case "$criterion" in
            user)      ctx_user="$value" ;;
            group)     ctx_user=$(first_member "$value") \
                           || unsupported="group $value has no members" ;;
            # The network address itself is inside its own range, so the mask
            # can simply be dropped.
            address)   ctx_addr=$(printf '%s' "$value" | cut -d/ -f1) ;;
            host)      ctx_host="$value" ;;
            localport) ctx_lport="$value" ;;
            *)         unsupported="$criterion is not a criterion sshd -C accepts" ;;
        esac
        shift 2
    done

    if [ -n "$unsupported" ]; then
        echo "MANUAL $line"
        echo "REASON $unsupported"
        continue
    fi

    # sshd -C always wants a user, so an Address-only block still needs one.
    # 'nobody' is preferred over the audited account because sshd applies every
    # block that matches, and using an account with group memberships would
    # pull in whatever a 'Match Group' block does as well.
    if [ -z "$ctx_user" ]; then
        if getent passwd nobody >/dev/null 2>&1; then
            ctx_user=nobody
        else
            ctx_user=$(id -un 2>/dev/null || echo root)
        fi
    fi
    context="user=$ctx_user"
    [ -n "$ctx_host" ]  && context="$context,host=$ctx_host"
    [ -n "$ctx_addr" ]  && context="$context,addr=$ctx_addr"
    [ -n "$ctx_lport" ] && context="$context,lport=$ctx_lport"

    resolved=""
    for candidate in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd sshd; do
        if [ -x "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
            resolved=$("$candidate" -T -C "$context" 2>/dev/null) && [ -n "$resolved" ] && break
            resolved=$(sudo -n "$candidate" -T -C "$context" 2>/dev/null) \
                && [ -n "$resolved" ] && break
            resolved=""
        fi
    done

    if [ -n "$resolved" ]; then
        echo "CONTEXT $context"
        echo "CRITERIA $line"
        printf '%s\n' "$resolved" | sed 's/^/SET /'
    else
        echo "MANUAL $line"
        echo "REASON sshd -T -C '$context' produced nothing"
    fi
done

emit MODULI
# The group the server picks for us is only the one it thought we wanted. The
# file says what else is on offer, which is what a less careful client could
# end up negotiating. Field five is the size in bits minus one.
for f in /etc/ssh/moduli /usr/local/etc/moduli /etc/moduli; do
    if [ -r "$f" ]; then
        echo "FILE $f"
        awk '!/^#/ && NF >= 7 { print $5 + 1 }' "$f" | sort -n | uniq -c \
            | awk '{ print "SIZE " $2 " " $1 }'
        break
    fi
done

emit PACKAGE
# Every version-based finding carries the caveat that distributions backport
# fixes without changing the advertised version. The package version is what
# settles it: 8.4p1-5+deb11u3 is a patched 8.4p1, and the changelog says which
# CVEs went in.
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f '${Package} ${Version}\n' openssh-server openssh-client 2>/dev/null \
        | while read -r name version; do echo "PKG dpkg $name $version"; done
elif command -v rpm >/dev/null 2>&1; then
    rpm -q --qf 'PKG rpm %{NAME} %{VERSION}-%{RELEASE}\n' openssh-server openssh 2>/dev/null \
        | grep '^PKG' || true
elif command -v apk >/dev/null 2>&1; then
    apk list --installed 2>/dev/null | awk '/^openssh/ { print "PKG apk " $1 }' | head -5
fi
for f in /etc/os-release /usr/lib/os-release; do
    if [ -r "$f" ]; then
        awk -F= '$1 == "PRETTY_NAME" { gsub(/"/, "", $2); print "OS " $2 }' "$f"
        break
    fi
done

emit CHANGELOG
# Which CVEs the installed package says it addressed.
#
# This is the answer to the caveat every version-based finding carries. The
# changelog shipped with a package documents that package's own history, so a
# CVE named in it was dealt with in this revision or an earlier one -- which is
# exactly what "the distribution backported the fix" means.
#
# Local files only: no network. A scan that reached out to a security tracker
# would be making a claim about a host it could not verify offline, and would
# fail differently every time the tracker was down.
CHANGELOG_TEXT=""
CHANGELOG_SOURCE=""
if command -v dpkg-query >/dev/null 2>&1; then
    for pkg in openssh-server openssh-client openssh; do
        for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
            if [ -r "$f" ]; then
                CHANGELOG_TEXT=$(gzip -dc "$f" 2>/dev/null) && [ -n "$CHANGELOG_TEXT" ] && \
                    CHANGELOG_SOURCE="$f" && break
            fi
        done
        [ -n "$CHANGELOG_SOURCE" ] && break
    done
elif command -v rpm >/dev/null 2>&1; then
    for pkg in openssh-server openssh; do
        CHANGELOG_TEXT=$(rpm -q --changelog "$pkg" 2>/dev/null) && [ -n "$CHANGELOG_TEXT" ] && \
            CHANGELOG_SOURCE="rpm -q --changelog $pkg" && break
    done
fi

if [ -n "$CHANGELOG_TEXT" ]; then
    echo "SOURCE $CHANGELOG_SOURCE"
    printf '%s\n' "$CHANGELOG_TEXT" \
        | grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' | sort -u | head -500 \
        | while read -r cve; do echo "CVE $cve"; done
else
    echo "NONE no changelog for the sshd package is readable on this host"
fi

emit ACCOUNTS
# Every account's authorized_keys, not just the audited one. This is where
# access accumulates: the audited account is the one somebody is looking
# after, and the other forty are the ones nobody has opened since 2019.
#
# Reading another user's file needs root, so each account is reported as read
# or not read. An account that could not be checked is said so rather than
# counted as clean.
READER="cat"
if [ "$(id -u)" != "0" ] && sudo -n true 2>/dev/null; then
    READER="sudo -n cat"
fi
AK_TEMPLATE=$(printf '%s\n' "$CONFIG_TEXT" | awk '$1=="authorizedkeysfile"{$1=""; print}')
[ -z "$AK_TEMPLATE" ] && AK_TEMPLATE=".ssh/authorized_keys .ssh/authorized_keys2"

accounts() {
    if command -v getent >/dev/null 2>&1; then
        getent passwd 2>/dev/null
    else
        cat /etc/passwd 2>/dev/null
    fi
}

accounts | awk -F: '{ print $1 ":" $3 ":" $6 ":" $7 }' | while IFS=: read -r user uid home shell; do
    # System accounts with no login shell cannot use a key even if one is
    # there, so listing them would be noise. Anything that can log in counts.
    case "$shell" in
        */nologin|*/false|"") continue ;;
    esac
    [ -d "$home" ] || continue
    for template in $AK_TEMPLATE; do
        f=$(printf '%s' "$template" | sed -e "s|%h|$home|g" -e "s|%d|$home|g" \
                                          -e "s|%u|$user|g" -e 's|%%|%|g')
        case "$f" in
            /*) ;;
            *) f="$home/$f" ;;
        esac
        [ -e "$f" ] || continue
        if content=$($READER "$f" 2>/dev/null) && [ -n "$content" ]; then
            echo "ACCOUNT $user $f"
            printf '%s\n' "$content" | sed 's/^/KEY /'
        else
            echo "UNREADABLE $user $f"
        fi
    done
done

emit USER-KEYS
# Private keys sitting on the host. One with no passphrase is a credential in
# a file: whoever reads it is that user everywhere the key is trusted, and no
# server-side setting changes that.
accounts | awk -F: '{ print $1 ":" $6 ":" $7 }' | while IFS=: read -r user home shell; do
    case "$shell" in
        */nologin|*/false|"") continue ;;
    esac
    [ -d "$home/.ssh" ] || continue
    for key in "$home"/.ssh/id_* "$home"/.ssh/*.pem; do
        case "$key" in
            *.pub|*"*"*) continue ;;
        esac
        [ -f "$key" ] || continue
        printf 'KEYFILE %s ' "$user"
        statline "$key" || echo "? ? ? $key"
        # An OpenSSH-format key names its cipher right after the magic string,
        # and 'none' means the private half is stored in the clear. A PEM key
        # says so in a header instead.
        header=$($READER "$key" 2>/dev/null | head -c 120)
        case "$header" in
            *"OPENSSH PRIVATE KEY"*)
                body=$($READER "$key" 2>/dev/null | sed -n '2p' | base64 -d 2>/dev/null \
                       | tr -d '\000' | head -c 40)
                case "$body" in
                    *none*) echo "ENCRYPTED $user no $key" ;;
                    "")     echo "ENCRYPTED $user unknown $key" ;;
                    *)      echo "ENCRYPTED $user yes $key" ;;
                esac
                ;;
            *ENCRYPTED*)          echo "ENCRYPTED $user yes $key" ;;
            *"PRIVATE KEY"*)      echo "ENCRYPTED $user no $key" ;;
            *)                    echo "ENCRYPTED $user unknown $key" ;;
        esac
        if [ -r "${key}.pub" ] && command -v ssh-keygen >/dev/null 2>&1; then
            # ssh-keygen prints "bits fingerprint comment (TYPE)", and the
            # comment can contain spaces, so the type is the last field rather
            # than the fourth.
            ssh-keygen -l -f "${key}.pub" 2>/dev/null | awk -v u="$user" -v k="$key" \
                '{ print "PUBKEY " u " " $1 " " $NF " " k }'
        fi
    done
done

emit END
"""


def _parse_sections(output: str) -> Dict[str, List[str]]:
    """Split the remote script's output into its labelled sections."""
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for line in output.splitlines():
        if line.startswith(_SECTION) and line.endswith("###"):
            current = line[len(_SECTION) : -3]
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return sections


def parse_effective_config(text: str) -> Dict[str, List[str]]:
    """Parse ``sshd -T`` output into directive to values.

    Directives are lower-cased, as ``sshd -T`` prints them. A few may appear
    more than once (``hostkey``, ``port``, ``listenaddress``), so every value
    is kept.
    """
    config: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(" ")
        config.setdefault(name.lower(), []).append(value.strip())
    return config


def parse_file_modes(lines: Sequence[str]) -> List[FileMode]:
    """Parse ``stat -c '%a %U %G %n'`` output.

    The path is last and everything after the third field belongs to it, so a
    file name containing a space is read whole instead of shifting the columns
    that follow it.
    """
    modes = []
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        modes.append(
            FileMode(
                path=" ".join(fields[3:]), mode=fields[0], owner=fields[1], group=fields[2]
            )
        )
    return modes


#: Prefixes of every public key type OpenSSH accepts in authorized_keys. Used
#: to tell "the line starts with options" from "the line starts with a key".
_KEY_TYPE_PREFIXES = ("ssh-", "ecdsa-", "sk-ecdsa-", "sk-ssh-", "rsa-sha2-", "webauthn-")


def _split_option_list(text: str) -> List[str]:
    """Split an authorized_keys option list on unquoted commas.

    ``command="/bin/x --flag=a,b",from="10.0.0.1"`` is two options, not three:
    the comma inside the quotes belongs to the command.
    """
    options: List[str] = []
    current: List[str] = []
    quoted = False
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\\" and quoted and index + 1 < len(text):
            current.append(text[index + 1])
            index += 2
            continue
        if character == '"':
            quoted = not quoted
        elif character == "," and not quoted:
            if current:
                options.append("".join(current).strip())
            current = []
            index += 1
            continue
        current.append(character)
        index += 1
    if current:
        options.append("".join(current).strip())
    return [option for option in options if option]


def _split_entry(line: str) -> Tuple[List[str], str]:
    """Separate the option list from the rest of the line."""
    if line.startswith(_KEY_TYPE_PREFIXES):
        return [], line

    quoted = False
    for index, character in enumerate(line):
        if character == "\\" and quoted:
            continue
        if character == '"':
            quoted = not quoted
        elif character in " \t" and not quoted:
            return _split_option_list(line[:index]), line[index:].strip()
    # No unquoted whitespace: there is no key on the line at all.
    return _split_option_list(line), ""


def _expiry_time(options: Sequence[str]) -> Optional[int]:
    """Read OpenSSH 8.2's ``expiry-time="YYYYMMDDHHMM[SS]"`` option.

    The timestamp is in the server's local time, which this tool cannot know,
    so it is read as UTC. The error is at most a day, and the option is used
    for month-scale lifetimes.
    """
    for option in options:
        name, _, value = option.partition("=")
        if name.strip().lower() != "expiry-time":
            continue
        digits = value.strip().strip('"')
        for layout in ("%Y%m%d%H%M%S", "%Y%m%d%H%M", "%Y%m%d"):
            try:
                parsed = datetime.strptime(digits, layout).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            return int(parsed.timestamp())
    return None


def parse_authorized_key(line: str) -> AuthorizedKeyEntry:
    """Parse one authorized_keys line.

    A line this tool cannot make sense of is reported as an entry with an
    error rather than dropped, because an unreadable line in a file that grants
    access is itself worth seeing.
    """
    options, remainder = _split_entry(line.strip())
    entry = AuthorizedKeyEntry(options=options)
    entry.is_certificate_authority = "cert-authority" in entry.option_names
    entry.expires_at = _expiry_time(options)

    fields = remainder.split()
    if not fields:
        entry.error = "no key on the line"
        return entry

    entry.key_type = fields[0]
    entry.comment = " ".join(fields[2:]) if len(fields) > 2 else ""
    if len(fields) < 2:
        entry.error = "no key material"
        return entry

    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError):
        entry.error = "key material is not valid base64"
        return entry

    try:
        info = parse_host_key_blob(blob, entry.key_type)
    except Exception as exc:  # a malformed key must not stop the audit
        entry.error = f"unreadable key: {exc}"
        return entry

    entry.bits = info.bits
    entry.key_family = info.key_family
    entry.fingerprint_sha256 = info.fingerprint_sha256
    entry.is_certificate = info.is_certificate
    if info.certificate is not None and info.certificate.valid_before is not None:
        # A certificate carries its own expiry; the option is only a second bound.
        if entry.expires_at is None:
            entry.expires_at = info.certificate.valid_before
        else:
            entry.expires_at = min(entry.expires_at, info.certificate.valid_before)
    return entry


def _parse_authorized_keys(
    lines: Sequence[str],
) -> Tuple[List[AuthorizedKeyEntry], Optional[FileMode]]:
    """Extract authorized_keys entries and the file's mode."""
    entries: List[AuthorizedKeyEntry] = []
    mode: Optional[FileMode] = None
    for line in lines:
        if line.startswith("MODE "):
            parsed = parse_file_modes([line[len("MODE ") :]])
            if parsed:
                mode = parsed[0]
            continue
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(parse_authorized_key(line))
    return entries, mode


def _parse_match_contexts(lines: Sequence[str]) -> List[MatchContext]:
    """Read the MATCH-RESOLVED section.

    A block that could not be turned into a context is kept with the reason,
    because "we did not look" and "we looked and it is fine" are different
    answers and only one of them is reassuring.
    """
    contexts: List[MatchContext] = []
    current: Optional[MatchContext] = None
    for line in lines:
        if line.startswith("CONTEXT "):
            current = MatchContext(context=line[len("CONTEXT ") :].strip())
            contexts.append(current)
        elif line.startswith("MANUAL "):
            current = MatchContext(criteria=line[len("MANUAL ") :].strip())
            contexts.append(current)
        elif line.startswith("CRITERIA ") and current is not None:
            current.criteria = line[len("CRITERIA ") :].strip()
        elif line.startswith("REASON ") and current is not None:
            current.error = line[len("REASON ") :].strip()
            current = None
        elif line.startswith("SET ") and current is not None:
            name, _, value = line[len("SET ") :].strip().partition(" ")
            if name:
                current.directives.setdefault(name.lower(), []).append(value.strip())
    return contexts


def _parse_moduli(lines: Sequence[str]) -> Optional[ModuliFile]:
    """Read the group sizes emitted by the MODULI section."""
    moduli = None
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "FILE" and len(fields) >= 2:
            moduli = ModuliFile(path=fields[1])
        elif fields[0] == "SIZE" and len(fields) >= 3 and moduli is not None:
            try:
                moduli.sizes[int(fields[1])] = int(fields[2])
            except ValueError:
                continue
    return moduli


def _parse_package(lines: Sequence[str]) -> Optional[PackageInfo]:
    """Read the PACKAGE section.

    The server package is preferred over the client one: this tool is auditing
    a server, and on some distributions they are versioned separately.
    """
    info = PackageInfo()
    best: Optional[PackageInfo] = None
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "PKG" and len(fields) >= 4:
            candidate = PackageInfo(manager=fields[1], name=fields[2], version=fields[3])
            if best is None or "server" in candidate.name:
                best = candidate
        elif fields[0] == "PKG" and len(fields) == 3:
            # apk prints one field: openssh-server-9.9_p2-r0
            best = best or PackageInfo(manager=fields[1], name=fields[2])
        elif fields[0] == "OS":
            info.os_name = " ".join(fields[1:])
    if best is None:
        return info if info.os_name else None
    best.os_name = info.os_name
    return best


def _parse_changelog(lines: Sequence[str]) -> Tuple[str, List[str], str]:
    """Read the CHANGELOG section: (source, CVE identifiers, error)."""
    source = ""
    error = ""
    identifiers: List[str] = []
    for line in lines:
        if line.startswith("SOURCE "):
            source = line[len("SOURCE ") :].strip()
        elif line.startswith("NONE "):
            error = line[len("NONE ") :].strip()
        elif line.startswith("CVE "):
            identifier = line[len("CVE ") :].strip().upper()
            if identifier and identifier not in identifiers:
                identifiers.append(identifier)
    return source, identifiers, error


def _parse_accounts(lines: Sequence[str]) -> Tuple[List[AccountKeys], List[str]]:
    """Read the ACCOUNTS section: every account's authorized_keys."""
    accounts: List[AccountKeys] = []
    unreadable: List[str] = []
    current: Optional[AccountKeys] = None
    for line in lines:
        if line.startswith("ACCOUNT "):
            fields = line.split(None, 2)
            if len(fields) >= 3:
                current = AccountKeys(username=fields[1], path=fields[2])
                accounts.append(current)
        elif line.startswith("UNREADABLE "):
            fields = line.split(None, 2)
            if len(fields) >= 2:
                unreadable.append(fields[1])
            current = None
        elif line.startswith("KEY ") and current is not None:
            entry = line[4:].strip()
            if entry and not entry.startswith("#"):
                current.entries.append(parse_authorized_key(entry))

    # A path with no %u resolves to the same file for every account, which is
    # what an AuthorizedKeysFile pointing at one shared file does. Report it
    # once, naming who shares it, rather than repeating the contents per user.
    by_path: Dict[str, AccountKeys] = {}
    collapsed: List[AccountKeys] = []
    for account in accounts:
        existing = by_path.get(account.path)
        if existing is None:
            by_path[account.path] = account
            collapsed.append(account)
        elif account.username not in existing.shared_with:
            existing.shared_with.append(account.username)
    return collapsed, unreadable


def _parse_user_keys(lines: Sequence[str]) -> List[UserPrivateKey]:
    """Read the USER-KEYS section: private keys sitting in home directories."""
    keys: Dict[Tuple[str, str], UserPrivateKey] = {}

    def get(username: str, path: str) -> UserPrivateKey:
        key = keys.get((username, path))
        if key is None:
            key = UserPrivateKey(username=username, path=path)
            keys[(username, path)] = key
        return key

    for line in lines:
        fields = line.split()
        if not fields:
            continue
        # The path is the last field on every one of these lines, for the
        # reason statline gives: a key called "id_ed25519 backup" used to be
        # read as the key called "id_ed25519", overwriting its type, its size
        # and whether it had a passphrase -- and vanishing itself.
        if fields[0] == "KEYFILE" and len(fields) >= 6:
            key = get(fields[1], " ".join(fields[5:]))
            parsed = parse_file_modes([" ".join(fields[2:])])
            if parsed:
                key.mode = parsed[0]
        elif fields[0] == "ENCRYPTED" and len(fields) >= 4:
            key = get(fields[1], " ".join(fields[3:]))
            key.encrypted = {"yes": True, "no": False}.get(fields[2])
        elif fields[0] == "PUBKEY" and len(fields) >= 5:
            key = get(fields[1], " ".join(fields[4:]))
            try:
                key.bits = int(fields[2])
            except ValueError:
                key.bits = None
            key.key_type = fields[3].strip("()")
    return list(keys.values())


def _build_ssh_command(
    host: str,
    port: int,
    credentials: Credentials,
    timeout: float,
    ssh_binary: str,
    extra_options: Sequence[str] = (),
) -> List[str]:
    """Build the local ``ssh`` invocation.

    Everything goes through an argument list rather than a shell, so a hostile
    inventory entry cannot inject a command locally.
    """
    command = [
        ssh_binary,
        # The remote script arrives on stdin, so ssh must not try to read a
        # terminal for it.
        "-p",
        str(port),
        "-o",
        f"ConnectTimeout={int(max(1, timeout))}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "LogLevel=ERROR",
        "-T",
    ]
    if credentials.identity_file:
        command += ["-o", "IdentitiesOnly=yes", "-i", os.path.expanduser(credentials.identity_file)]

    mode = credentials.mode.value
    if mode == "key":
        command += ["-o", "PreferredAuthentications=publickey", "-o", "BatchMode=yes"]
    elif mode == "password":
        command += ["-o", "PreferredAuthentications=password,keyboard-interactive",
                    "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
    elif not credentials.has_password_source:
        # Nothing to answer a prompt with, so fail rather than hang.
        command += ["-o", "BatchMode=yes"]

    command += list(extra_options)
    target = f"{credentials.username}@{host}" if credentials.username else host
    return [*command, target, "/bin/sh"]


def _askpass_environment(password: str) -> Tuple[Dict[str, str], str]:
    """An SSH_ASKPASS helper that reads the secret from the environment.

    The password is never written to disk: the helper script contains only a
    reference to an environment variable, which is readable by this user alone.
    """
    with tempfile.NamedTemporaryFile(
        "w", suffix=".sh", delete=False, prefix="sshcc-askpass-"
    ) as handle:
        handle.write('#!/bin/sh\nprintf "%s" "$SSHCC_PASSWORD"\n')
    os.chmod(handle.name, 0o700)

    environment = dict(os.environ)
    environment.update(
        {
            "SSHCC_PASSWORD": password,
            "SSH_ASKPASS": handle.name,
            "SSH_ASKPASS_REQUIRE": "force",
            # Older ssh only consults SSH_ASKPASS when it believes there is a
            # display and no terminal.
            "DISPLAY": environment.get("DISPLAY", ":0"),
        }
    )
    return environment, handle.name


def fetch_effective_config(
    host: str,
    port: int,
    credentials: Credentials,
    timeout: float = 15.0,
    ssh_binary: Optional[str] = None,
    connect_host: Optional[str] = None,
    connect_port: Optional[int] = None,
) -> EffectiveConfig:
    """Log in and read the server's effective configuration.

    Never raises for an unreachable or unauthorised server: the failure is
    recorded on the result so one inaccessible host does not stop an audit.
    """
    result = EffectiveConfig(attempted=True, username=credentials.username or "")
    binary = ssh_binary or shutil.which("ssh")
    if binary is None:
        result.error = "no ssh client found on this machine, which this audit delegates to"
        return result

    password: Optional[str] = None
    if credentials.mode.value == "password" or credentials.has_password_source:
        try:
            password = credentials.resolve_password()
        except ValueError as exc:
            result.error = str(exc)
            return result
    if credentials.mode.value == "password" and not password:
        result.error = "auth=password was requested but no password-file or password-env was set"
        return result

    # When a bastion is in the way the scan has already opened a forward to
    # this target, so the audit goes through the same one rather than making a
    # second jump of its own. ProxyJump would not do: ssh builds the inner
    # command itself and passes almost none of our options to it, so the
    # bastion's host key could not be handled the way the caller asked.
    #
    # HostKeyAlias keeps the key recorded under the real name. Without it,
    # known_hosts fills with entries for ephemeral local ports and the target's
    # own key is never checked against anything.
    extra: List[str] = []
    if connect_host is not None:
        extra = ["-o", f"HostKeyAlias={host}"]
    command = _build_ssh_command(
        connect_host or host,
        connect_port or port,
        credentials,
        timeout,
        binary,
        extra,
    )
    environment = dict(os.environ)
    askpass_path: Optional[str] = None
    if password is not None:
        environment, askpass_path = _askpass_environment(password)

    try:
        completed = subprocess.run(
            command,
            input=REMOTE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=max(timeout * 3, 30),
            env=environment,
        )
    except subprocess.TimeoutExpired:
        result.error = "the ssh client did not finish in time"
        return result
    except OSError as exc:
        result.error = f"could not run the ssh client: {exc}"
        return result
    except Exception as exc:  # this function promises never to raise
        # One unreadable configuration must not turn a reachable server into an
        # unreachable one in the report.
        result.error = f"the configuration audit failed: {exc}"
        return result
    finally:
        if askpass_path:
            # missing_ok covers the only failure worth surviving: somebody
            # else removed the temporary file first.
            pathlib.Path(askpass_path).unlink(missing_ok=True)

    if completed.returncode != 0 and not completed.stdout.strip():
        # ssh relays the server's own words here -- "Received disconnect from
        # ... : <whatever the server said>" -- so this line is peer text on its
        # way to a terminal, like everything else the scan reports.
        detail = printable((completed.stderr or "").strip()).splitlines()
        result.error = (
            "ssh failed: " + (detail[-1] if detail else f"exit code {completed.returncode}")
        )
        return result

    try:
        return _read_sections(result, completed.stdout)
    except Exception as exc:  # this function promises never to raise
        # The promise in the docstring covers the parsing as well as the ssh
        # call. Nothing a server sends should get here -- every shape of output
        # has its own handling above -- but a defect in one of the parsers must
        # cost this audit and not turn a reachable server into an unreachable
        # one in the report.
        result.available = False
        result.error = f"the configuration audit failed: {exc}"
        return result


def _read_sections(result: EffectiveConfig, output: str) -> EffectiveConfig:
    """Fill in ``result`` from the remote script's output.

    The transcript is cleaned of control characters before anything reads it.
    Every field below -- a directive's value, a key's comment, an account
    name, a file path, a package version -- comes from a script running on the
    machine being audited, and ends up printed on somebody's terminal. A host
    that has been compromised is exactly the host this audit is pointed at,
    and it should not be able to write on the screen of the person looking
    into it.
    """
    sections = _parse_sections(printable(output, keep_newlines=True))
    raw = "\n".join(sections.get("SSHD-T", []))
    if "SSHCC-ERROR" in raw or not raw.strip():
        error_line = next(
            (line for line in raw.splitlines() if line.startswith("SSHCC-ERROR")), ""
        )
        result.error = error_line.replace("SSHCC-ERROR: ", "") or (
            "the server returned no configuration"
        )
        return result

    result.directives = parse_effective_config(raw)
    result.file_modes = parse_file_modes(sections.get("FILES", []))
    result.authorized_keys, authorized_mode = _parse_authorized_keys(
        sections.get("AUTHORIZED-KEYS", [])
    )
    if authorized_mode is not None:
        result.file_modes.append(authorized_mode)
    result.match_contexts = _parse_match_contexts(sections.get("MATCH-RESOLVED", []))
    result.moduli = _parse_moduli(sections.get("MODULI", []))
    result.package = _parse_package(sections.get("PACKAGE", []))
    source, changelog_cves, changelog_error = _parse_changelog(sections.get("CHANGELOG", []))
    if result.package is None and (source or changelog_error):
        result.package = PackageInfo()
    if result.package is not None:
        result.package.changelog_source = source
        result.package.changelog_cves = changelog_cves
        result.package.changelog_error = changelog_error
    result.accounts, result.unreadable_accounts = _parse_accounts(sections.get("ACCOUNTS", []))
    result.user_keys = _parse_user_keys(sections.get("USER-KEYS", []))
    result.match_blocks = [
        line.strip()
        for line in sections.get("MATCH-BLOCKS", [])
        if re.search(r"\bmatch\b", line, re.IGNORECASE)
    ]
    result.include_directives = [
        line.strip()
        for line in sections.get("MATCH-BLOCKS", [])
        if re.search(r"\binclude\b", line, re.IGNORECASE)
    ]
    result.available = True
    return result
