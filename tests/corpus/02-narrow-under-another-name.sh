# --narrow is consumed only under the trigger name; as sh, ash or dash it
# must reach the shell's own option parser and fail there, identically to
# upstream.
"$SH" --narrow readonly -c 'echo must-not-run'
echo "exit=$?"
