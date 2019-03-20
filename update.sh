#!/bin/bash
set -e

prod=
OPTS=`getopt -n 'update.sh' -o p -l prod -- "$@"`
eval set -- "$OPTS"
while true; do
    case "$1" in
        -p | --prod )     prod="1" ; shift 1 ;;
        -- )              shift; break ;;
        * )               echo "Invalid option: -$1" >&2 ; exit 1 ;;
    esac
done

# See https://packaging.python.org/tutorials/packaging-projects/
python3 setup.py sdist
if [ -z "${prod}" ]; then
    python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
else
    twine upload dist/*
fi
