"""Create the coding-agent data directories as the runtime user, then exec the command.

Nothing here runs as root. The workspace volume already belongs to the runtime user when the
container starts: the fragment declares x-sealed-owner on it, and sealed-agent creates
/mnt/sealed-data/coding-agent/<volume> with that owner before it releases the ready gate
(integration brief item 11). This creates the directories in SEALED_OWNED_DIRS that do not exist
yet (a symlink planted there is removed, never followed), refuses directories owned by another
user (so a missing x-sealed-owner fails loudly), sets no_new_privs (the composer also sets
no-new-privileges; this checks it), changes to SEALED_WORKDIR when set, and execs argv. Embedded
verbatim in the compose fragment.
"""
import ctypes
import os
import pwd
import stat
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39


class PrepError(Exception):
    pass


def parse_ids(spec):
    try:
        uid_text, gid_text = spec.split(":", 1)
        uid, gid = int(uid_text), int(gid_text)
    except ValueError:
        raise PrepError("SEALED_RUN_AS must be uid:gid, got " + repr(spec))
    if uid <= 0 or gid <= 0:
        raise PrepError("SEALED_RUN_AS must name a non-root uid and gid")
    return uid, gid


def owned_dirs(value):
    dirs = [d.strip() for d in value.split(",") if d.strip()]
    for d in dirs:
        if not os.path.isabs(d) or ".." in d.split("/"):
            raise PrepError("SEALED_OWNED_DIRS entries must be absolute paths: " + repr(d))
    return dirs


def prepare(dirs, uid):
    """Create missing directories as the current user; every directory must be ours."""
    for path in dirs:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            os.unlink(path)
            st = None
        if st is not None and not stat.S_ISDIR(st.st_mode):
            raise PrepError(path + " exists and is not a directory")
        if st is None:
            os.mkdir(path, 0o755)
            st = os.lstat(path)
        if st.st_uid != uid:
            raise PrepError(path + " is owned by uid " + str(st.st_uid) + ", not " + str(uid)
                            + " (is x-sealed-owner applied to the volume?)")


def set_no_new_privs():
    """prctl(PR_SET_NO_NEW_PRIVS, 1): exec can no longer grant privileges (setuid, file caps)."""
    if not sys.platform.startswith("linux"):
        raise PrepError("no_new_privs needs Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise PrepError("prctl(PR_SET_NO_NEW_PRIVS) failed: errno " + str(ctypes.get_errno()))
    if libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise PrepError("no_new_privs did not take effect")


def home_of(uid):
    try:
        return pwd.getpwuid(uid).pw_dir
    except KeyError:
        return "/tmp"


def workdir(env, dirs):
    path = env.get("SEALED_WORKDIR", "")
    if not path:
        return None
    if path not in dirs:
        raise PrepError("SEALED_WORKDIR must be one of SEALED_OWNED_DIRS, got " + repr(path))
    return path


def main(argv=None, env=None, execvp=os.execvp, getuid=os.getuid, getgid=os.getgid,
         no_new_privs=set_no_new_privs, chdir=os.chdir):
    argv = list(sys.argv if argv is None else argv)
    env = os.environ if env is None else env
    if len(argv) < 2:
        print("prepdirs: usage: prepdirs <command> [args...]", file=sys.stderr)
        return 2
    try:
        uid, gid = parse_ids(env.get("SEALED_RUN_AS", "10001:10001"))
        dirs = owned_dirs(env.get("SEALED_OWNED_DIRS", ""))
        target = workdir(env, dirs)
        current = (getuid(), getgid())
        if current[0] == 0:
            raise PrepError("runs as root; the fragment must set user to " + str(uid) + ":" + str(gid))
        if current != (uid, gid):
            raise PrepError("started as " + str(current[0]) + ":" + str(current[1]) + "; expected "
                            + str(uid) + ":" + str(gid))
        prepare(dirs, uid)
        no_new_privs()
        if target:
            chdir(target)
    except (PrepError, OSError, AttributeError) as err:
        print("prepdirs: " + str(err), file=sys.stderr)
        return 1
    env["HOME"] = home_of(uid)
    sys.stderr.flush()
    execvp(argv[1], argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
