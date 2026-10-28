"""Prepare the coding-agent data directories as root, drop to the runtime user, exec the command.

The composer turns named volumes into bind mounts that start out owned by root, while the
agent runs as uid 10001. This runs first (as root, after envexec), creates the directories
in SEALED_OWNED_DIRS, hands them to SEALED_RUN_AS, drops every privilege and execs argv.
Symlinks planted inside the volume are removed, never followed. Embedded verbatim in the
compose fragment.
"""
import os
import pwd
import stat
import sys


class DropError(Exception):
    pass


def parse_ids(spec):
    try:
        uid_text, gid_text = spec.split(":", 1)
        uid, gid = int(uid_text), int(gid_text)
    except ValueError:
        raise DropError("SEALED_RUN_AS must be uid:gid, got " + repr(spec))
    if uid <= 0 or gid <= 0:
        raise DropError("SEALED_RUN_AS must name a non-root uid and gid")
    return uid, gid


def owned_dirs(value):
    dirs = [d.strip() for d in value.split(",") if d.strip()]
    for d in dirs:
        if not os.path.isabs(d) or ".." in d.split("/"):
            raise DropError("SEALED_OWNED_DIRS entries must be absolute paths: " + repr(d))
    return dirs


def prepare(dirs, uid, gid):
    for path in dirs:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            os.unlink(path)
            st = None
        if st is not None and not stat.S_ISDIR(st.st_mode):
            raise DropError(path + " exists and is not a directory")
        if st is None:
            os.mkdir(path, 0o755)
        os.chown(path, uid, gid, follow_symlinks=False)


def drop(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getuid() != uid or os.geteuid() != uid or os.getgid() != gid:
        raise DropError("privilege drop did not take effect")
    try:
        os.setuid(0)
    except PermissionError:
        return
    raise DropError("could regain root after the drop")


def home_of(uid):
    try:
        return pwd.getpwuid(uid).pw_dir
    except KeyError:
        return "/tmp"


def main(argv=None, env=None, execvp=os.execvp, getuid=os.getuid):
    argv = list(sys.argv if argv is None else argv)
    env = os.environ if env is None else env
    if len(argv) < 2:
        print("dropuid: usage: dropuid <command> [args...]", file=sys.stderr)
        return 2
    try:
        uid, gid = parse_ids(env.get("SEALED_RUN_AS", "10001:10001"))
        dirs = owned_dirs(env.get("SEALED_OWNED_DIRS", ""))
        current = getuid()
        if current == 0:
            prepare(dirs, uid, gid)
            drop(uid, gid)
        elif current != uid:
            raise DropError("started as uid " + str(current) + "; expected root or " + str(uid))
    except (DropError, OSError) as err:
        print("dropuid: " + str(err), file=sys.stderr)
        return 1
    env["HOME"] = home_of(uid)
    sys.stderr.flush()
    execvp(argv[1], argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
