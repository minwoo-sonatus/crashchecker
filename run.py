#!/usr/bin/python3

import argparse
import os
import sys
import subprocess
import hashlib
import time
import pwd
import grp
import tempfile
import datetime

HEAPTRACK_URL = "https://github.com/KDE/heaptrack/releases/download/v1.5.0/heaptrack-1.5.0-Linux.deb"

# Default GitHub repository owner and name
GITHUB_REPO = os.environ.get("GITHUB_REPO", "minwoo-lee/crashchecker")

# Pre-built image from GitHub Container Registry
CONTAINER_IMAGE_URL = f"ghcr.io/{GITHUB_REPO}/dbg-container:latest"

# Keep the Dockerfile content for reference and for GitHub Actions to build
DOCKERFILE_CONTENT = """
FROM ubuntu:24.10

# install build tools (including gcc and g++)
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    sudo less curl python3 python3-psutil ca-certificates elfutils unzip xz-utils vim tree tmux ssh iproute2 \
    net-tools gdb gdb-multiarch locales binutils fish rpm2cpio rpm cpio debuginfod lldb git \
    libboost-program-options1.83.0

# setup user to match host user name and user id
# set superuser permissions for new user
ARG USER_NAME
ARG USER_ID
ARG GROUP_NAME
ARG GROUP_ID
ARG HOST
ARG USER_HOME
ARG SONATUS_GID
ARG SONATUS_GNAME

RUN if [ "$HOST" = "Linux" ] ; then \
    groupadd -f sudo && \
    groupadd -f --system --gid ${GROUP_ID} ${GROUP_NAME} || true && \
    useradd \
        --uid ${USER_ID} \
        --shell /bin/bash \
        --home ${USER_HOME} \
        --groups sudo \
        --create-home ${USER_NAME} || true && \
    echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers ; \
fi

RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# debuginfod envs
ENV DEBUGINFOD_URLS="http://builder-kr-2.kr.sonatus.com:8002 http://127.0.0.1:8002"
ENV HEAPTRACK_ENABLE_DEBUGINFOD=1

USER ${USER_NAME}

# Install pwndbg
RUN cd ${USER_HOME} && git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Install heaptrack via apt-get instead of copying
RUN sudo apt-get update && sudo apt-get install -y wget && \
    cd /tmp && wget -q -O heaptrack.deb ${HEAPTRACK_URL} && \
    sudo dpkg -i heaptrack.deb || sudo apt-get -f install -y && \
    rm heaptrack.deb

CMD [ "/bin/bash" ]
"""

class DockerManager:
    def __init__(self):
        self.script_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
        self.user_name = pwd.getpwuid(os.getuid()).pw_name
        self.user_id = os.getuid()
        self.group_name = grp.getgrgid(os.getgid()).gr_name
        self.group_id = os.getgid()
        self.user_home = os.path.expanduser("~")
        self.config_dir = os.path.join(self.user_home, ".config", "coredump_analyzer")
        self.debuginfod_db_path = os.path.join(self.config_dir, ".debuginfod.sqlite")
        self.config_hash = self.get_config_hash()
        self.docker_image = CONTAINER_IMAGE_URL
        self.local_docker_image = f"{self.user_name}-dbg-container-local-{self.config_hash}"
        self.docker_container = self.get_container_name()
        self.tier = "lge"
        self.yocto_rpm_deploy_postfix = "build_s32g274aevb/tmp/deploy/rpm/"
        self.container_prefix = f"home_{self.user_name}_dbg-container"
        self.use_prebuilt_image = True  # Use prebuilt image by default

        os.makedirs(self.config_dir, exist_ok=True)

    def get_config_hash(self):
        """Calculate hash from script content and Dockerfile"""
        # Include both the script content and Dockerfile content in the hash
        content = ""

        # Add script content
        with open(__file__, 'r') as f:
            script_content = f.read()
            filtered_script = "\n".join([line for line in script_content.splitlines()
                                      if line.strip() and not line.strip().startswith('#')])
            content += filtered_script

        # Add Dockerfile content
        filtered_dockerfile = "\n".join([line for line in DOCKERFILE_CONTENT.splitlines()
                                       if line.strip() and not line.strip().startswith('#')])
        content += filtered_dockerfile

        return hashlib.sha1(content.encode()).hexdigest()

    def get_container_name(self):
        """Generate container name based on mount directory and config hash"""
        container_name = f"{self.script_dir.replace('/', '_').replace(' ', '_')}-{self.config_hash}"
        if container_name.startswith('_'):
            container_name = container_name[1:]
        return container_name

    def container_exists(self):
        """Check if container exists"""
        try:
            result = subprocess.run(['docker', 'container', 'inspect', self.docker_container],
                                    capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def container_running(self):
        """Check if container is running"""
        try:
            result = subprocess.run(['docker', 'inspect', '-f', '{{.State.Running}}', self.docker_container],
                                    capture_output=True, text=True)
            return result.returncode == 0 and result.stdout.strip() == 'true'
        except:
            return False

    def ensure_container_running(self):
        """Start container if not running"""
        if not self.container_running():
            print(f"Starting container {self.docker_container}...")
            subprocess.run(['docker', 'start', self.docker_container], check=True)

    def remove_container(self):
        """Remove container if it exists"""
        if self.container_exists():
            print(f"Removing existing container {self.docker_container}...")
            if self.container_running():
                subprocess.run(['docker', 'stop', self.docker_container], check=True)
            subprocess.run(['docker', 'rm', self.docker_container], check=True)
            print(f"Container {self.docker_container} removed")
            return True
        return False

    def schedule_system_cleanup(self, days):
        """Schedule container cleanup using system at/cron command for long term scheduling"""
        if days <= 0:
            return False

        # Calculate the date when cleanup should happen
        future_date = datetime.datetime.now() + datetime.timedelta(days=days)

        # Create the cleanup command
        cleanup_script = os.path.join(self.config_dir, f"cleanup_{self.docker_container}.sh")

        # Create cleanup script
        with open(cleanup_script, 'w') as f:
            f.write(f"""#!/bin/bash
# Auto-generated cleanup script for {self.docker_container}
# Scheduled to run on {future_date.strftime('%Y-%m-%d %H:%M')}

# Check if the container exists and hasn't been used in {days} days
CONTAINER_NAME="{self.docker_container}"
LAST_USED=$(docker inspect --format='{{{{.State.FinishedAt}}}}' "$CONTAINER_NAME" 2>/dev/null)

if [ -z "$LAST_USED" ]; then
    echo "Container $CONTAINER_NAME not found. Cleaning up this script."
    rm "$0"
    exit 0
fi

# Check if container is running - if it's running, we assume it's being used
IS_RUNNING=$(docker inspect --format='{{{{.State.Running}}}}' "$CONTAINER_NAME" 2>/dev/null)
if [ "$IS_RUNNING" = "true" ]; then
    echo "Container $CONTAINER_NAME is still running. Keeping it alive."
    exit 0
fi

# Stop and remove container
echo "Removing unused container $CONTAINER_NAME"
docker rm "$CONTAINER_NAME"

# Remove this script after execution
rm "$0"
""")

        # Make the script executable
        os.chmod(cleanup_script, 0o755)

        # Schedule with at command
        at_time = future_date.strftime('%H:%M %Y-%m-%d')
        try:
            # Check if at command is available
            at_check = subprocess.run(['which', 'at'], capture_output=True, text=True)

            if at_check.returncode == 0:
                print(f"Scheduling container cleanup after {days} days using 'at' command")
                # Use at command for scheduling
                at_cmd = f"echo {cleanup_script} | at {at_time}"
                subprocess.run(at_cmd, shell=True, check=True)
                print(f"Container will be automatically removed after {days} days of inactivity")
                return True
            else:
                # Fall back to cron if at is not available
                print("The 'at' command is not available. Setting up a cron job instead.")
                crontab_line = f"{future_date.minute} {future_date.hour} {future_date.day} {future_date.month} * {cleanup_script}"

                # Add to crontab
                current_crontab = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                if current_crontab.returncode != 0:
                    current_crontab_content = ""
                else:
                    current_crontab_content = current_crontab.stdout

                # Append the new cron job
                new_crontab = current_crontab_content.strip() + f"\n{crontab_line}\n"

                with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                    tmp.write(new_crontab)
                    tmp_path = tmp.name

                subprocess.run(['crontab', tmp_path], check=True)
                os.unlink(tmp_path)

                print(f"Container will be automatically removed after {days} days of inactivity (using cron)")
                return True

        except Exception as e:
            print(f"Failed to schedule cleanup: {e}")
            print("Container will not be automatically removed.")
            if os.path.exists(cleanup_script):
                os.unlink(cleanup_script)
            return False

    def remove_all_dbg_containers(self):
        """Remove all containers that start with home_username_dbg-container"""
        print(f"Removing all containers starting with {self.container_prefix}...")

        # Get all containers
        try:
            # List all containers and extract names starting with the prefix
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f"name={self.container_prefix}", '--format', '{{.Names}}'],
                capture_output=True, text=True, check=True
            )

            containers = result.stdout.strip().split('\n')
            containers = [c for c in containers if c]  # Filter out empty lines

            if not containers:
                print("No debug containers found to remove.")
                return False

            # Stop running containers first
            for container in containers:
                try:
                    # Check if container is running
                    running_check = subprocess.run(
                        ['docker', 'inspect', '-f', '{{.State.Running}}', container],
                        capture_output=True, text=True, check=True
                    )

                    if running_check.stdout.strip() == 'true':
                        print(f"Stopping container: {container}")
                        subprocess.run(['docker', 'stop', container], check=True)

                    print(f"Removing container: {container}")
                    subprocess.run(['docker', 'rm', container], check=True)
                except Exception as e:
                    print(f"Error processing container {container}: {e}")

            print(f"Removed {len(containers)} debug containers")
            return True
        except Exception as e:
            print(f"Error removing containers: {e}")
            return False

    def create_container(self, force_new=False, remove_all=False):
        """Create docker image and container if they don't exist"""
        print(f"Docker container name: {self.docker_container}")

        # Remove containers based on options
        if remove_all:
            self.remove_all_dbg_containers()
        elif force_new:
            self.remove_container()

        # Try to pull the pre-built image
        if self.use_prebuilt_image:
            print(f"Pulling pre-built image from GitHub Container Registry: {self.docker_image}")
            pull_result = subprocess.run(['docker', 'pull', self.docker_image], capture_output=True)

            if pull_result.returncode != 0:
                print("Failed to pull pre-built image. Falling back to building locally.")
                self.use_prebuilt_image = False
                self.docker_image = self.local_docker_image

        # If using local image, build if needed
        if not self.use_prebuilt_image:
            # Pull Ubuntu image
            subprocess.run(['docker', 'pull', 'ubuntu:24.10'], check=True)

            # Check if image exists
            result = subprocess.run(['docker', 'images', '-q', self.docker_image], capture_output=True, text=True)
            image_id = result.stdout.strip()

            # Build image if it doesn't exist
            if not image_id:
                print(f"Building docker image locally: {self.docker_image}")

                # Create a temporary directory for the Docker build context
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Create a temporary Dockerfile
                    dockerfile_path = os.path.join(temp_dir, 'Dockerfile')
                    with open(dockerfile_path, 'w') as f:
                        f.write(DOCKERFILE_CONTENT.replace('${HEAPTRACK_URL}', HEAPTRACK_URL))

                    # Build the Docker image
                    build_cmd = [
                        'docker', 'build', '-t', self.docker_image,
                        '--build-arg', f'USER_NAME={self.user_name}',
                        '--build-arg', f'USER_ID={self.user_id}',
                        '--build-arg', f'GROUP_NAME={self.group_name}',
                        '--build-arg', f'GROUP_ID={self.group_id}',
                        '--build-arg', f'USER_HOME={self.user_home}',
                        '--build-arg', 'HOST=Linux',
                        temp_dir
                    ]
                    subprocess.run(build_cmd, check=True)
                    print(f"Done building docker image: {self.docker_image}")

        # Check if container exists
        if not self.container_exists():
            print(f"Creating container: {self.docker_container}")
            create_cmd = [
                'docker', 'create', '-it',
                '--volume', f"{self.user_home}:{self.user_home}:rw",
                '--volume', f"{self.script_dir}:{self.script_dir}",
                '--volume', '/opt:/opt:ro',
                '--volume', '/etc/timezone:/etc/timezone:ro',
                '--volume', '/etc/localtime:/etc/localtime:ro',
                '--volume', '/var/run/docker.sock:/var/run/docker.sock',
                '--security-opt', 'seccomp=unconfined',
                '--privileged',
                '--name', self.docker_container,
                self.docker_image
            ]
            subprocess.run(create_cmd, check=True)

            # Add debuginfod config to .gdbinit if it doesn't exist
            gdbinit_content = (
                "set debuginfod enabled on\n"
                "set auto-load safe-path /:rootfs\n"
                "set print pretty on\n"
                "set print object on\n"
                "set print static-members on\n"
                "set print vtbl on\n"
                "set print demangle on\n"
                "set demangle-style gnu-v3\n"
                "set print sevenbit-strings off\n"
            )
            gdbinit_path = os.path.join(self.user_home, '.gdbinit')
            write_gdbinit = True

            if os.path.exists(gdbinit_path):
                with open(gdbinit_path, 'r') as f:
                    if 'debuginfod' in f.read():
                        write_gdbinit = False

            if write_gdbinit:
                with open(gdbinit_path, 'a') as f:
                    f.write(gdbinit_content)

            # Start the container
            subprocess.run(['docker', 'start', self.docker_container], check=True)
        else:
            print("Container already exists, skipping creation")

    def run_command_in_container(self, command, working_dir=None):
        """Run command inside the container"""
        cmd = ['docker', 'exec']

        if working_dir:
            cmd.extend(['-w', working_dir])

        cmd.extend(['-it', self.docker_container])
        cmd.extend(command if isinstance(command, list) else command.split())

        return subprocess.run(cmd)

    def analyze_coredump(self, coredump_file=None, force_new_container=False, remove_all_containers=False,
                         auto_cleanup_days=0, rpms=None, vendor_files=None, yocto_manifest=None):
        """Analyze the core dump file with GDB or just start the container if no coredump file"""
        # Ensure container exists and is running
        if not self.container_exists() or force_new_container or remove_all_containers:
            self.create_container(force_new=force_new_container, remove_all=remove_all_containers)
        else:
            self.ensure_container_running()

        # Set up system-level cleanup if requested
        if auto_cleanup_days > 0:
            self.schedule_system_cleanup(auto_cleanup_days)

        # First, start symbol server in the container
        self.start_symbol_server_in_container(rpms, vendor_files, yocto_manifest)

        # If no coredump file provided, we're done (container is running)
        if coredump_file is None:
            return None

        # Then run gdb-multiarch with the coredump file
        print(f"Starting GDB analysis of {coredump_file}...")

        # Get the absolute path to the coredump file
        coredump_path = os.path.abspath(coredump_file)

        # Run gdb-multiarch with the command directly
        gdb_cmd = [
            '/bin/bash', '-c',
            f'gdb-multiarch -ex "thread apply all bt" -c "{coredump_path}"'
        ]

        return self.run_command_in_container(gdb_cmd, self.script_dir)

    def start_symbol_server_in_container(self, rpms=None, vendor_files=None, yocto_manifest=None):
        """Start the debuginfod symbol server inside the container"""
        print("Starting symbol server...")

        # First ensure any existing debuginfod processes are terminated
        self.run_command_in_container([
            '/bin/bash', '-c',
            "pgrep debuginfod && pkill debuginfod || true"
        ])

        # Create the debuginfod command
        debuginfod_cmd = self.create_debuginfod_command(rpms, vendor_files, yocto_manifest)

        # Run the debuginfod server in the container
        self.run_command_in_container([
            '/bin/bash', '-c',
            f"DEBUGINFOD_URLS= {debuginfod_cmd} >/dev/null 2>&1 &"
        ])

        # Give the symbol server a moment to start
        time.sleep(2)

    def create_debuginfod_command(self, rpms=None, vendor_files=None, yocto_manifest=None):
        """Create the debuginfod command with all the appropriate flags"""
        # Base command with default paths - use config directory for debuginfod.sqlite
        cmd = f"debuginfod -d {self.debuginfod_db_path} -L -R rpms/ -F vendor/"

        # Add additional RPM directories if specified
        if rpms:
            for rpm_path in rpms:
                cmd += f" -R {rpm_path}"

        # Add additional vendor files if specified
        if vendor_files:
            for vendor_path in vendor_files:
                cmd += f" -F {vendor_path}"

        # Add yocto manifest if specified
        if yocto_manifest and os.path.isdir(f"{yocto_manifest}/{self.tier}/{self.yocto_rpm_deploy_postfix}"):
            cmd += f" -R {yocto_manifest}/{self.tier}/{self.yocto_rpm_deploy_postfix}"

        print(f"Debuginfod command: {cmd}")
        return cmd

    def setup_rpms_and_vendor_dirs(self):
        """Create rpms and vendor directories if they don't exist"""
        rpms_dir = os.path.join(self.script_dir, 'rpms')
        vendor_dir = os.path.join(self.script_dir, 'vendor')

        if not os.path.exists(rpms_dir):
            os.makedirs(rpms_dir, exist_ok=True)
            print(f"Created rpms directory: {rpms_dir}")

        if not os.path.exists(vendor_dir):
            os.makedirs(vendor_dir, exist_ok=True)
            print(f"Created vendor directory: {vendor_dir}")


def parse_args():
    parser = argparse.ArgumentParser(description='Analyze coredump files inside Docker container')
    parser.add_argument('coredump_file', nargs='?', help='Path to the coredump file to analyze')
    parser.add_argument('-N', '--new-container', action='store_true',
                        help='Force create a new container, removing ALL existing debug containers')
    parser.add_argument('-T', '--auto-remove-days', type=int, default=0, metavar='DAYS',
                        help='Automatically remove the container after specified days of inactivity (default: 2 days)')
    parser.add_argument('-l', '--local-build', action='store_true',
                        help='Build Docker image locally instead of using pre-built image')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Start an interactive shell in the container instead of analyzing a coredump')
    parser.add_argument('-R', dest="rpms", action='extend', nargs='+', type=str,
                        help='Specify local rpms path')
    parser.add_argument('-F', dest="vendor", action='extend', nargs='+', type=str,
                        help='Specify local vendor files(executables, symbols)')
    parser.add_argument('-t', '--tier', dest='tier', default="lge", type=str,
                        help='Specify yocto manifest tier for CCU2')
    parser.add_argument('-m', '--yocto-manifest', dest='yocto_manifest', default="", type=str,
                        help='Specify local yocto manifest path')

    args = parser.parse_args()

    # Default to 2 days if -T is provided without a value
    if args.auto_remove_days < 0:
        args.auto_remove_days = 2

    return args


def main():
    if os.geteuid() == 0:
        print("Please do not run as root.")
        sys.exit(1)

    args = parse_args()

    # Initialize Docker manager
    docker_manager = DockerManager()
    if args.tier:
        docker_manager.tier = args.tier

    # Use local build if specified
    if args.local_build:
        docker_manager.use_prebuilt_image = False
        docker_manager.docker_image = docker_manager.local_docker_image

    # Ensure rpms and vendor directories exist
    docker_manager.setup_rpms_and_vendor_dirs()

    # If no coredump file is provided, just start the container in interactive mode
    if args.coredump_file is None or args.interactive:
        print("No coredump file provided or interactive mode specified. Starting container shell...")
        if not docker_manager.container_exists() or args.new_container:
            docker_manager.create_container(force_new=False, remove_all=args.new_container)
        else:
            docker_manager.ensure_container_running()

        # Start an interactive shell in the container
        subprocess.run([
            'docker', 'exec', '-it', docker_manager.docker_container, '/bin/bash'
        ])
    else:
        # Analyze the coredump file
        docker_manager.analyze_coredump(
            args.coredump_file,
            force_new_container=False,
            remove_all_containers=args.new_container,
            auto_cleanup_days=args.auto_remove_days,
            rpms=args.rpms,
            vendor_files=args.vendor,
            yocto_manifest=args.yocto_manifest
        )

if __name__ == "__main__":
    main()