from django.core.management.base import BaseCommand, CommandError
from sliver.models import ImplantTemplate, TaskTemplate


class Command(BaseCommand):
    help = 'Create default implant and task templates for Sliver operations'

    def handle(self, *args, **options):
        self.stdout.write('Creating default Sliver templates...')

        # Create default implant templates
        self.stdout.write('Creating implant templates...')
        implant_templates = [
            {
                'name': 'windows-x64-beacon',
                'description': 'Windows x64 beacon implant',
                'config': {
                    'os': 'windows',
                    'arch': 'amd64',
                    'format': 'exe',
                    'is_beacon': True,
                    'debug': False,
                    'obfuscate': True,
                },
                'operating_system': 'windows',
                'architecture': 'amd64',
                'is_default': True,
            },
            {
                'name': 'windows-x64-session',
                'description': 'Windows x64 interactive session implant',
                'config': {
                    'os': 'windows',
                    'arch': 'amd64',
                    'format': 'exe',
                    'is_beacon': False,
                    'debug': False,
                    'obfuscate': True,
                },
                'operating_system': 'windows',
                'architecture': 'amd64',
                'is_default': False,
            },
            {
                'name': 'linux-x64-beacon',
                'description': 'Linux x64 beacon implant',
                'config': {
                    'os': 'linux',
                    'arch': 'amd64',
                    'format': 'elf',
                    'is_beacon': True,
                    'debug': False,
                    'obfuscate': False,
                },
                'operating_system': 'linux',
                'architecture': 'amd64',
                'is_default': False,
            },
            {
                'name': 'linux-x64-session',
                'description': 'Linux x64 interactive session implant',
                'config': {
                    'os': 'linux',
                    'arch': 'amd64',
                    'format': 'elf',
                    'is_beacon': False,
                    'debug': False,
                    'obfuscate': False,
                },
                'operating_system': 'linux',
                'architecture': 'amd64',
                'is_default': False,
            },
            {
                'name': 'macos-x64-beacon',
                'description': 'macOS x64 beacon implant',
                'config': {
                    'os': 'darwin',
                    'arch': 'amd64',
                    'format': 'macho',
                    'is_beacon': True,
                    'debug': False,
                    'obfuscate': False,
                },
                'operating_system': 'darwin',
                'architecture': 'amd64',
                'is_default': False,
            },
            {
                'name': 'macos-arm64-beacon',
                'description': 'macOS ARM64 beacon implant',
                'config': {
                    'os': 'darwin',
                    'arch': 'arm64',
                    'format': 'macho',
                    'is_beacon': True,
                    'debug': False,
                    'obfuscate': False,
                },
                'operating_system': 'darwin',
                'architecture': 'arm64',
                'is_default': False,
            },
        ]

        for template_data in implant_templates:
            template, created = ImplantTemplate.objects.get_or_create(
                name=template_data['name'],
                defaults=template_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  Created implant template: {template.name}'))
            else:
                # Update existing template
                for key, value in template_data.items():
                    setattr(template, key, value)
                template.save()
                self.stdout.write(f'  Updated implant template: {template.name}')

        # Create default task templates
        self.stdout.write('Creating task templates...')
        task_templates = [
            {
                'name': 'System Information',
                'description': 'Get detailed system information from target',
                'command': 'sysinfo',
                'category': 'recon',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'List Directory',
                'description': 'List files and directories in a path',
                'command': 'ls {path}',
                'category': 'recon',
                'parameters': {'path': '/'},
                'is_builtin': True,
            },
            {
                'name': 'Whoami',
                'description': 'Show current user identity',
                'command': 'whoami',
                'category': 'recon',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Show Process List',
                'description': 'Display running processes',
                'command': 'ps',
                'category': 'recon',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Network Information',
                'description': 'Show network interfaces and connections',
                'command': 'netstat -tuln && ip addr show',
                'category': 'recon',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Download File',
                'description': 'Download a file from the target system',
                'command': 'download {remote_path}',
                'category': 'loot',
                'parameters': {'remote_path': '/path/to/file'},
                'is_builtin': True,
            },
            {
                'name': 'Upload File',
                'description': 'Upload a file to the target system',
                'command': 'upload {local_path} {remote_path}',
                'category': 'execution',
                'parameters': {'local_path': 'local_file.txt', 'remote_path': 'remote_file.txt'},
                'is_builtin': True,
            },
            {
                'name': 'Execute Command',
                'description': 'Execute a shell command on the target',
                'command': '{shell_command}',
                'category': 'execution',
                'parameters': {'shell_command': 'echo "Hello World"'},
                'is_builtin': True,
            },
            {
                'name': 'Execute PowerShell',
                'description': 'Execute PowerShell commands on Windows targets',
                'command': 'powershell.exe -nop -enc {encoded_command}',
                'category': 'execution',
                'parameters': {'encoded_command': 'powershell_encoded_command'},
                'is_builtin': True,
            },
            {
                'name': 'Screenshot',
                'description': 'Capture screenshot of the target desktop',
                'command': 'screenshot',
                'category': 'recon',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Port Scan',
                'description': 'Perform port scan on network targets using nmap',
                'command': 'nmap -sV -p- {target}',
                'category': 'recon',
                'parameters': {'target': '127.0.0.1'},
                'is_builtin': True,
            },
            {
                'name': 'Privilege Elevation Check',
                'description': 'Check current privilege level and suggest elevation methods',
                'command': 'getprivs',
                'category': 'privesc',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Browser Credentials',
                'description': 'Extract saved credentials from web browsers',
                'command': 'creds -browser',
                'category': 'loot',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'WiFi Passwords',
                'description': 'Extract saved WiFi passwords',
                'command': 'wifi',
                'category': 'loot',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Keylogger Start',
                'description': 'Start keylogger to capture keystrokes',
                'command': 'keylogger start',
                'category': 'monitoring',
                'parameters': {},
                'is_builtin': True,
            },
            {
                'name': 'Get Clipboard',
                'description': 'Retrieve current clipboard contents',
                'command': 'clipboard',
                'category': 'recon',
                'parameters': {},
                'is_builtin': True,
            },
        ]

        for template_data in task_templates:
            template, created = TaskTemplate.objects.get_or_create(
                name=template_data['name'],
                defaults=template_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f'  Created task template: {template.name}'))
            else:
                # Update existing template
                for key, value in template_data.items():
                    setattr(template, key, value)
                template.save()
                self.stdout.write(f'  Updated task template: {template.name}')

        self.stdout.write(self.style.SUCCESS(
            'Successfully created/updated default templates for Sliver operations!'
        ))
        self.stdout.write('Total implant templates created: {}'.format(len(implant_templates)))
        self.stdout.write('Total task templates created: {}'.format(len(task_templates)))
