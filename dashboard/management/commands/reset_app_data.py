from __future__ import annotations

from typing import Iterable, Set

from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction


class Command(BaseCommand):
    help = (
        "Delete application data while preserving Django auth users and password hashes. "
        "This truncates dashboard/sliver data plus sessions and admin log entries."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Required confirmation flag for destructive execution.",
        )

    def handle(self, *args, **options):
        if not options["force"]:
            raise CommandError("Refusing to delete data without --force.")

        tables = sorted(self._collect_tables())
        if not tables:
            self.stdout.write(self.style.WARNING("No application tables found to reset."))
            return

        vendor = connection.vendor
        quoted_tables = ", ".join(connection.ops.quote_name(table) for table in tables)

        with transaction.atomic():
            with connection.cursor() as cursor:
                if vendor == "postgresql":
                    cursor.execute(f"TRUNCATE TABLE {quoted_tables} RESTART IDENTITY CASCADE")
                elif vendor == "sqlite":
                    cursor.execute("PRAGMA foreign_keys = OFF")
                    for table in tables:
                        cursor.execute(f"DELETE FROM {connection.ops.quote_name(table)}")
                    cursor.execute(
                        "DELETE FROM sqlite_sequence WHERE name IN (%s)"
                        % ", ".join(["%s"] * len(tables)),
                        tables,
                    )
                    cursor.execute("PRAGMA foreign_keys = ON")
                else:
                    raise CommandError(f"Unsupported database vendor for reset_app_data: {vendor}")

        self.stdout.write(
            self.style.SUCCESS(
                "Deleted application data from dashboard/sliver tables while preserving Django auth users."
            )
        )

    def _collect_tables(self) -> Set[str]:
        table_names: Set[str] = set()
        for model in self._reset_models():
            if model._meta.managed and not model._meta.proxy:
                table_names.add(model._meta.db_table)
        return table_names

    def _reset_models(self) -> Iterable[type]:
        reset_app_labels = {"dashboard", "sliver"}
        extra_models = {
            ("admin", "LogEntry"),
            ("sessions", "Session"),
        }

        for model in apps.get_models(include_auto_created=False):
            app_label = model._meta.app_label
            object_name = model._meta.object_name
            if app_label in reset_app_labels or (app_label, object_name) in extra_models:
                yield model
