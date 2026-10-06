# -c with $0 and positional parameters
"$SH" -c 'echo "$0" "$#" "$@"' zero a b c
