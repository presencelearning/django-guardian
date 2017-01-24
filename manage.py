#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                          "guardian.testapp.testsettings")

    from django.core.management import execute_from_command_line

    # normal usage is ./manage.py test guardian
    if len(sys.argv) == 2 and sys.argv[1] == 'test':
        sys.argv.append('guardian')

    execute_from_command_line(sys.argv)
