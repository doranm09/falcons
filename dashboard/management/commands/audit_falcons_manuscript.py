from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Fail when FALCONS publication outputs are missing or still contain unresolved values."

    REQUIRED_MACROS = {
        "FalconsDigitalComponentCount",
        "FalconsPhysicalComponentCount",
        "FalconsFlowCount",
        "FalconsFunctionCount",
        "FalconsTimeStepDuration",
        "FalconsAssetCount",
        "FalconsSOneAssetCVE",
        "FalconsSOnePi",
        "FalconsTelemetryBaseline",
        "FalconsTelemetryDegraded",
        "FalconsBestMitigation",
        "FalconsMitigationReduction",
        "FalconsMedianInferenceTime",
        "FalconsGPWRThresholds",
    }

    def add_arguments(self, parser):
        parser.add_argument(
            "--journal-dir",
            default=str(Path(settings.BASE_DIR) / "journal_iee_itt"),
        )

    def handle(self, *args, **options):
        journal_dir = Path(options["journal_dir"])
        tex_path = journal_dir / "FALCONS_IEEE_TII.tex"
        generated = journal_dir / "generated"
        macro_path = generated / "falcons_results_macros.tex"
        table_paths = [
            generated / "falcons_vulnerability_rows.tex",
            generated / "falcons_telemetry_rows.tex",
        ]
        missing_files = [str(path) for path in [tex_path, macro_path, *table_paths] if not path.is_file()]
        if missing_files:
            raise CommandError("Missing publication files: " + ", ".join(missing_files))

        macro_text = macro_path.read_text(encoding="utf-8")
        unresolved_tokens = ("TBD", "[Insert", "[Confirm", "unavailable")
        found_tokens = [token for token in unresolved_tokens if token in macro_text]
        if found_tokens:
            raise CommandError("Generated result macros remain unresolved: " + ", ".join(found_tokens))

        missing_macros = [
            name for name in sorted(self.REQUIRED_MACROS)
            if f"\\renewcommand{{\\{name}}}" not in macro_text
        ]
        if missing_macros:
            raise CommandError("Missing generated macros: " + ", ".join(missing_macros))

        for table_path in table_paths:
            table_text = table_path.read_text(encoding="utf-8").strip()
            if not table_text or any(token in table_text for token in unresolved_tokens):
                raise CommandError(f"Generated table is empty or unresolved: {table_path}")

        tex_text = tex_path.read_text(encoding="utf-8")
        direct_markers = [
            line_number
            for line_number, line in enumerate(tex_text.splitlines(), 1)
            if ("\\resulttodo{" in line or "\\methodtodo{" in line)
            and not line.lstrip().startswith("\\newcommand")
        ]
        if direct_markers:
            raise CommandError(f"Direct manuscript TODO macros remain at lines: {direct_markers}")

        self.stdout.write(self.style.SUCCESS("FALCONS manuscript result bundle is publication-complete."))
