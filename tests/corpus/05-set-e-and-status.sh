# errexit, exit status propagation, and an unknown option
"$SH" -c 'set -e; false; echo not-reached'
echo "exit=$?"
"$SH" -Z -c 'echo must-not-run'
echo "exit=$?"
