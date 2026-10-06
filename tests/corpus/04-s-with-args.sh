# -s with positional parameters from the command line
printf 'echo "$1-$2"\n' | "$SH" -s first second
