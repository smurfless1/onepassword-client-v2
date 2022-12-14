import os
import subprocess
import shlex


def read_bash_return(cmd, session_key_var: str, session_key: str, single=True) -> str:
    my_env = os.environ.copy()
    my_env[session_key_var] = session_key

    try:
        result = subprocess.run(cmd,
                                shell=True,
                                check=False,
                                env=my_env,
                                capture_output=True,
                                timeout=5,
                                input='',
                                )
        combined = str(result.stdout.decode('utf-8')) + str(result.stderr.decode('utf-8'))
        if single:
            return combined.splitlines(False)[0]
        else:
            return combined

    except subprocess.TimeoutExpired as tee:
        print(tee)


def limited_bash_return(cmd, session_key_var: str, session_key: str, single=True) -> str:
    my_env = os.environ.copy()
    my_env[session_key_var] = session_key

    try:
        result = subprocess.run(shlex.split(cmd),
                                check=False,
                                env=my_env,
                                timeout=5,
                                )
        #combined = str(result.stdout.decode('utf-8')) + str(result.stderr.decode('utf-8'))
        #if single:
        #    return combined.splitlines(False)[0]
        #else:
        #    return combined

    except subprocess.TimeoutExpired as tee:
        print(tee)


def domain_from_email(address):
    """
    Method to extract a domain without sld or tld from an email address

    :param address: email address to extract from
    :type address: str

    :return: domain (str)
    """
    return address.split("@")[1].split(".")[0]


def bump_version(version_type="patch"):
    """
    Only run in the project root directory, this is for github to bump the version file only!

    :return:
    """
    __root__ = os.path.abspath("")
    with open(os.path.join(__root__, 'VERSION')) as version_file:
        version = version_file.read().strip()

    all_version = version.replace('"', "").split(".")
    new_all_version = version.split(".")[:-1]
    new_all_version.append(str(int(all_version[-1]) + 1))
    if version_type == "minor":
        new_all_version = [version.split(".")[0]]
        new_all_version.extend([str(int(all_version[1]) + 1), '0'])
    new_line = '.'.join(new_all_version) + "\n"
    with open("{}/VERSION".format(__root__), "w") as fp:
        fp.write(new_line)
    fp.close()


def generate_uuid():
    """
    Generates a random UUID to be used for op in initial set up only for more details read here
    https://1password.community/discussion/114059/device-uuid

    :return: (str)
    """
    return read_bash_return(
        "head -c 16 /dev/urandom | base32 | tr -d = | tr '[:upper:]' '[:lower:]'",
        "", ""
    )


def get_device_uuid(bp):
    """
    Attempts to get the device_uuid from the given BashProfile. If the device_uuid is not
    set in the BashProfile generates a new device_uuid and sets it in the given
    BashProfile.

    :return: (str)
    """
    try:
        device_uuid = bp.get_key_value("OP_DEVICE")[0]['OP_DEVICE'].strip('"')
        if device_uuid is None:
            device_uuid = generate_uuid()
            bp.update_profile("OP_DEVICE", device_uuid)
    except (AttributeError, ValueError, KeyError):
        device_uuid = generate_uuid()
        bp.update_profile("OP_DEVICE", device_uuid)

    return device_uuid


def docker_check() -> bool:
    """Return True if it looks like the OS is run from inside docker"""
    f = None
    user_home = os.environ.get('HOME')
    for rcfile in ['.bashrc', '.bash_profile', '.zshrc', '.zprofile']:
        rcpath = os.path.join(user_home, rcfile)
        if os.path.exists(rcpath):
            f = open(os.path.join(user_home, rcpath), "r")
            break
    if not f:
        raise Exception("No shell rc or profile files exist.")
    bash_profile = f.read()
    try:
        docker_flag = bash_profile.split('DOCKER_FLAG="')[1][0]
        if docker_flag == "t":
            return True
        else:
            return False
    except IndexError:
        return False
