# a leading "-" in argv[0] (login shell) must not confuse the name gate;
# the profile files are not read because -c runs with a controlled HOME
HOME=/nonexistent "$SH" -l -c 'echo login-style "$0"' 2>&1
