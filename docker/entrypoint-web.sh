#!/usr/bin/env sh
set -e

cd /code

python cyber_pen_test/manage.py collectstatic --noinput
python cyber_pen_test/manage.py migrate
python setup_sliver.py

exec daphne -b 0.0.0.0 -p 8000 cyber_pen_test.asgi:application
