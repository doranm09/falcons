from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from dashboard.falcons_experiments import ExperimentError, FalconsExperimentRunner, SCENARIOS, load_manifest


class Command(BaseCommand):
    help = "Run the publication-grade FALCONS S0-S4 experiment suite."

    def add_arguments(self, parser):
        parser.add_argument("--manifest", required=True, type=Path)
        parser.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
        parser.add_argument("--repetitions", type=int)
        parser.add_argument("--output-dir", type=Path)
        parser.add_argument("--no-wait", action="store_true")
        parser.add_argument("--allow-mutations", action="store_true")
        parser.add_argument("--skip-benchmarks", action="store_true")

    def handle(self, *args, **options):
        scenarios = SCENARIOS if options["scenario"] == "all" else (options["scenario"],)
        try:
            runner = FalconsExperimentRunner(
                manifest=load_manifest(options["manifest"]),
                scenarios=scenarios,
                repetitions=options.get("repetitions"),
                output_dir=options.get("output_dir"),
                no_wait=options["no_wait"],
                allow_mutations=options["allow_mutations"],
                skip_benchmarks=options["skip_benchmarks"],
            )
            suite = runner.run()
        except ExperimentError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"FALCONS suite {suite.suite_id} completed: {suite.output_dir}"))
