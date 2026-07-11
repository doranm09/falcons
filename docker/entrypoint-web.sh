#!/usr/bin/env sh
set -e

cd /code

python cyber_pen_test/manage.py migrate
python setup_sliver.py

if [ "${DJANGO_LIVE_RELOAD:-0}" = "1" ]; then
  exec python cyber_pen_test/manage.py runserver 0.0.0.0:8000
fi

python cyber_pen_test/manage.py collectstatic --noinput

exec daphne -b 0.0.0.0 -p 8000 cyber_pen_test.asgi:application
