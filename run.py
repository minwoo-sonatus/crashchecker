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
GITHUB_REPO = os.environ.get("GITHUB_REPO", "minwoo-sonatus/crashchecker")

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

# environment variables for user setup
ENV USER_NAME=""
ENV USER_ID=""
ENV GROUP_NAME=""
ENV GROUP_ID=""
ENV USER_HOME=""
ENV HOST=""

RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# debuginfod envs
ENV DEBUGINFOD_URLS="http://builder-kr-2.kr.sonatus.com:8002 http://127.0.0.1:8002"

# Install pwndbg
RUN git clone https://github.com/pwndbg/pwndbg /tmp/pwndbg && \
    cd /tmp/pwndbg && \
    ./setup.sh

# Create entrypoint script
RUN echo '#!/bin/bash\n\
# 디버깅을 위한 로그 출력\n\
LOG_FILE="/tmp/entrypoint.log"\n\
echo "================ CONTAINER STARTUP $(date) ================" > $LOG_FILE\n\
echo "Starting entrypoint script with parameters: $@" >> $LOG_FILE\n\
echo "Environment variables:" >> $LOG_FILE\n\
echo "USER_NAME=${USER_NAME}" >> $LOG_FILE\n\
echo "USER_ID=${USER_ID}" >> $LOG_FILE\n\
echo "GROUP_NAME=${GROUP_NAME}" >> $LOG_FILE\n\
echo "GROUP_ID=${GROUP_ID}" >> $LOG_FILE\n\
echo "USER_HOME=${USER_HOME}" >> $LOG_FILE\n\
echo "HOST=${HOST}" >> $LOG_FILE\n\
\n\
# 사용자 설정\n\
if [ "$HOST" = "Linux" ] && [ -n "$USER_NAME" ] && [ -n "$USER_ID" ]; then\n\
    echo "$(date +%T) - Setting up user ${USER_NAME} with ID ${USER_ID}" >> $LOG_FILE\n\
    \n\
    echo "$(date +%T) - Creating sudo group" >> $LOG_FILE\n\
    groupadd -f sudo\n\
    if [ $? -ne 0 ]; then\n\
        echo "$(date +%T) - ERROR: Failed to create sudo group" >> $LOG_FILE\n\
    fi\n\
    \n\
    echo "$(date +%T) - Creating user group ${GROUP_NAME} with GID ${GROUP_ID}" >> $LOG_FILE\n\
    groupadd -f --system --gid ${GROUP_ID} ${GROUP_NAME} || true\n\
    \n\
    echo "$(date +%T) - Creating user ${USER_NAME} with UID ${USER_ID}" >> $LOG_FILE\n\
    useradd \\\n\
        --uid ${USER_ID} \\\n\
        --shell /bin/bash \\\n\
        --home ${USER_HOME} \\\n\
        --groups sudo \\\n\
        --create-home ${USER_NAME} || true\n\
    \n\
    if [ $? -ne 0 ]; then\n\
        echo "$(date +%T) - WARNING: User creation may have failed or user already exists" >> $LOG_FILE\n\
        echo "$(date +%T) - Checking if user exists" >> $LOG_FILE\n\
        id ${USER_NAME} >> $LOG_FILE 2>&1\n\
    fi\n\
    \n\
    echo "$(date +%T) - Adding sudo permissions" >> $LOG_FILE\n\
    echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers\n\
    \n\
    echo "$(date +%T) - User setup completed" >> $LOG_FILE\n\
else\n\
    echo "$(date +%T) - Skipping user setup, required variables not set." >> $LOG_FILE\n\
    echo "  HOST=${HOST}" >> $LOG_FILE\n\
    echo "  USER_NAME=${USER_NAME}" >> $LOG_FILE\n\
    echo "  USER_ID=${USER_ID}" >> $LOG_FILE\n\
fi\n\
\n\
# 컨테이너가 실행 상태를 유지하도록 함\n\
if [ -z "$1" ] || [ "$1" = "/bin/bash" ]; then\n\
    echo "$(date +%T) - Starting bash session" >> $LOG_FILE\n\
    if [ -n "$USER_NAME" ]; then\n\
        echo "$(date +%T) - Attempting to switch to user ${USER_NAME}" >> $LOG_FILE\n\
        \n\
        # su 명령이 실패하더라도 컨테이너가 종료되지 않도록 함\n\
        if su ${USER_NAME} -c "bash"; then\n\
            echo "$(date +%T) - Successfully switched to user ${USER_NAME}" >> $LOG_FILE\n\
        else\n\
            echo "$(date +%T) - Failed to switch to user ${USER_NAME}, falling back to root" >> $LOG_FILE\n\
            bash\n\
        fi\n\
    else\n\
        echo "$(date +%T) - No user specified, running as root" >> $LOG_FILE\n\
        bash\n\
    fi\n\
else\n\
    echo "$(date +%T) - Running command: $@" >> $LOG_FILE\n\
    exec "$@"\n\
fi' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD [ "/bin/bash" ]
"""

class DockerManager:
    def __init__(self):
        print("Initializing DockerManager...")
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

        print(f"User info: {self.user_name}(uid={self.user_id}), {self.group_name}(gid={self.group_id})")
        print(f"Container name: {self.docker_container}")
        print(f"Image name: {self.docker_image}")
        print(f"Local image name: {self.local_docker_image}")
        
        os.makedirs(self.config_dir, exist_ok=True)
        print(f"Config directory: {self.config_dir}")

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

        hash_value = hashlib.sha1(content.encode()).hexdigest()
        print(f"Generated config hash: {hash_value}")
        return hash_value

    def get_container_name(self):
        """Generate container name based on mount directory and config hash"""
        container_name = f"{self.script_dir.replace('/', '_').replace(' ', '_')}-{self.config_hash}"
        if container_name.startswith('_'):
            container_name = container_name[1:]
        print(f"Generated container name: {container_name}")
        return container_name

    def container_exists(self):
        """Check if container exists"""
        try:
            print(f"Checking if container '{self.docker_container}' exists...")
            result = subprocess.run(['docker', 'container', 'inspect', self.docker_container],
                                    capture_output=True, text=True)
            exists = result.returncode == 0
            print(f"Container exists: {exists}")
            return exists
        except Exception as e:
            print(f"Error checking if container exists: {e}")
            return False

    def container_running(self):
        """Check if container is running"""
        try:
            print(f"Checking if container '{self.docker_container}' is running...")
            result = subprocess.run(['docker', 'inspect', '-f', '{{.State.Running}}', self.docker_container],
                                    capture_output=True, text=True)
            running = result.returncode == 0 and result.stdout.strip() == 'true'
            print(f"Container running: {running}")
            return running
        except Exception as e:
            print(f"Error checking if container is running: {e}")
            return False

    def ensure_container_running(self):
        """Start container if not running"""
        if not self.container_running():
            print(f"Starting container {self.docker_container}...")
            start_result = subprocess.run(['docker', 'start', self.docker_container], 
                                         capture_output=True, text=True, check=True)
            print(f"Start command output: {start_result.stdout}")
            
            # 컨테이너 시작 후 상태 다시 확인
            time.sleep(2)
            if not self.container_running():
                print(f"WARNING: Container failed to start or stopped immediately.")
                print("Container logs:")
                log_cmd = ['docker', 'logs', self.docker_container]
                subprocess.run(log_cmd)
            else:
                print(f"Container {self.docker_container} started successfully.")
        else:
            print(f"Container {self.docker_container} is already running.")

    def remove_container(self):
        """Remove container if it exists"""
        if self.container_exists():
            print(f"Removing existing container {self.docker_container}...")
            if self.container_running():
                print(f"Container is running. Stopping it first...")
                subprocess.run(['docker', 'stop', self.docker_container], check=True)
            remove_result = subprocess.run(['docker', 'rm', self.docker_container], 
                                          capture_output=True, text=True, check=True)
            print(f"Remove command output: {remove_result.stdout}")
            print(f"Container {self.docker_container} removed")
            return True
        print(f"Container {self.docker_container} does not exist, nothing to remove.")
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
        print(f"\n===== CONTAINER CREATION PROCESS =====")
        print(f"Docker container name: {self.docker_container}")
        print(f"Force new: {force_new}, Remove all: {remove_all}")

        # Remove containers based on options
        if remove_all:
            print("Removing all existing debug containers...")
            self.remove_all_dbg_containers()
        elif force_new:
            print("Forcing new container creation...")
            self.remove_container()

        container_existed = self.container_exists()
        print(f"Container already existed: {container_existed}")

        # Try to pull the pre-built image
        if self.use_prebuilt_image:
            print(f"Pulling pre-built image from GitHub Container Registry: {self.docker_image}")
            pull_result = subprocess.run(['docker', 'pull', self.docker_image], 
                                         capture_output=True, text=True)
            
            if pull_result.returncode != 0:
                print(f"Failed to pull pre-built image. Error: {pull_result.stderr}")
                print("Falling back to building locally.")
                self.use_prebuilt_image = False
                self.docker_image = self.local_docker_image
            else:
                print(f"Successfully pulled image: {self.docker_image}")

        # If using local image, build if needed
        if not self.use_prebuilt_image:
            # Pull Ubuntu image
            print("Pulling Ubuntu base image...")
            subprocess.run(['docker', 'pull', 'ubuntu:24.10'], check=True)

            # Check if image exists
            print(f"Checking if local image {self.docker_image} exists...")
            result = subprocess.run(['docker', 'images', '-q', self.docker_image], 
                                   capture_output=True, text=True)
            image_id = result.stdout.strip()
            
            if image_id:
                print(f"Local image found with ID: {image_id}")
            else:
                print(f"Local image not found. Building docker image: {self.docker_image}")

            # Build image if it doesn't exist
            if not image_id:
                print(f"Building docker image locally: {self.docker_image}")

                # Create a temporary directory for the Docker build context
                with tempfile.TemporaryDirectory() as temp_dir:
                    print(f"Created temporary directory for Docker build: {temp_dir}")
                    
                    # Create a temporary Dockerfile
                    dockerfile_path = os.path.join(temp_dir, 'Dockerfile')
                    print(f"Writing Dockerfile to: {dockerfile_path}")
                    with open(dockerfile_path, 'w') as f:
                        f.write(DOCKERFILE_CONTENT)

                    # Build the Docker image (without build-args)
                    build_cmd = [
                        'docker', 'build', '-t', self.docker_image,
                        temp_dir
                    ]
                    print(f"Running build command: {' '.join(build_cmd)}")
                    build_result = subprocess.run(build_cmd, capture_output=True, text=True, check=True)
                    print(f"Build stdout: {build_result.stdout}")
                    if build_result.stderr:
                        print(f"Build stderr: {build_result.stderr}")
                    print(f"Done building docker image: {self.docker_image}")

        # Check if container exists
        if not self.container_exists():
            print(f"\n===== CREATING NEW CONTAINER =====")
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
                # 환경 변수로 사용자 정보 전달
                '-e', f'USER_NAME={self.user_name}',
                '-e', f'USER_ID={self.user_id}',
                '-e', f'GROUP_NAME={self.group_name}',
                '-e', f'GROUP_ID={self.group_id}',
                '-e', f'USER_HOME={self.user_home}',
                '-e', 'HOST=Linux',
                '--name', self.docker_container,
                self.docker_image
            ]
            print(f"Running create command: docker create -it ... {self.docker_image}")
            create_result = subprocess.run(create_cmd, capture_output=True, text=True, check=True)
            print(f"Create container result: {create_result.stdout}")
            if create_result.stderr:
                print(f"Create container stderr: {create_result.stderr}")

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
                print(f"Found existing .gdbinit file: {gdbinit_path}")
                with open(gdbinit_path, 'r') as f:
                    content = f.read()
                    if 'debuginfod' in content:
                        print("Found debuginfod settings in existing .gdbinit, skipping update")
                        write_gdbinit = False
                    else:
                        print("No debuginfod settings found in .gdbinit, will append")

            if write_gdbinit:
                print(f"Writing debuginfod settings to .gdbinit: {gdbinit_path}")
                with open(gdbinit_path, 'a') as f:
                    f.write(gdbinit_content)

            # Start the container
            print(f"\n===== STARTING CONTAINER =====")
            print(f"Starting container {self.docker_container}...")
            start_result = subprocess.run(['docker', 'start', self.docker_container], 
                                         capture_output=True, text=True, check=True)
            print(f"Start container result: {start_result.stdout}")
            if start_result.stderr:
                print(f"Start container stderr: {start_result.stderr}")
            
            # 컨테이너가 제대로 시작되었는지 확인
            print("Waiting for container to initialize...")
            time.sleep(2)  # 컨테이너 시작 대기
            
            if not self.container_running():
                print("\n===== CONTAINER STARTUP FAILED =====")
                print("컨테이너가 시작되었지만 곧바로 종료되었습니다. 로그를 확인하세요.")
                print("Container logs:")
                log_cmd = ['docker', 'logs', self.docker_container]
                subprocess.run(log_cmd)
                
                print("\nChecking container state details...")
                inspect_cmd = ['docker', 'inspect', '--format', '{{.State}}', self.docker_container]
                subprocess.run(inspect_cmd)
            else:
                print(f"\n===== CONTAINER STARTED SUCCESSFULLY =====")
                print(f"컨테이너 {self.docker_container}가 성공적으로 시작되었습니다.")
                
                # Install heaptrack if this is a new container
                print("\n===== INSTALLING HEAPTRACK =====")
                self.install_heaptrack()
        else:
            print(f"Container {self.docker_container} already exists, skipping creation")
        
        # 컨테이너가 실행 중인지 다시 확인
        if not self.container_running():
            print("\n===== CONTAINER NOT RUNNING =====")
            print("컨테이너가 실행 중이 아닙니다. 시작합니다...")
            self.ensure_container_running()
        else:
            print("\n===== CONTAINER READY =====")
            print(f"Container {self.docker_container} is running and ready to use.")

    def run_command_in_container(self, command, working_dir=None):
        """Run command inside the container"""
        print(f"\n===== RUNNING COMMAND IN CONTAINER =====")
        
        cmd = ['docker', 'exec']

        if working_dir:
            print(f"Working directory: {working_dir}")
            cmd.extend(['-w', working_dir])

        cmd.extend(['-it', self.docker_container])
        cmd.extend(command if isinstance(command, list) else command.split())
        
        cmd_str = ' '.join(cmd)
        print(f"Executing command: {cmd_str}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print(f"Command finished with return code: {result.returncode}")
        if result.stdout:
            print(f"Command stdout (truncated if large):\n{result.stdout[:1000]}")
            if len(result.stdout) > 1000:
                print(f"... (output truncated, total length: {len(result.stdout)} bytes)")
        
        if result.stderr:
            print(f"Command stderr (truncated if large):\n{result.stderr[:1000]}")
            if len(result.stderr) > 1000:
                print(f"... (error output truncated, total length: {len(result.stderr)} bytes)")
        
        return result

    def analyze_coredump(self, coredump_file=None, force_new_container=False, remove_all_containers=False,
                         auto_cleanup_days=0, rpms=None, vendor_files=None, yocto_manifest=None):
        """Analyze the core dump file with GDB or just start the container if no coredump file"""
        print("\n===== COREDUMP ANALYSIS =====")
        print(f"Coredump file: {coredump_file if coredump_file else 'None'}")
        print(f"Force new container: {force_new_container}")
        print(f"Remove all containers: {remove_all_containers}")
        print(f"Auto cleanup days: {auto_cleanup_days}")
        print(f"RPMs: {rpms}")
        print(f"Vendor files: {vendor_files}")
        print(f"Yocto manifest: {yocto_manifest}")
        
        # Ensure container exists and is running
        print("\nChecking container status...")
        if not self.container_exists() or force_new_container or remove_all_containers:
            print("Container needs to be created or recreated")
            self.create_container(force_new=force_new_container, remove_all=remove_all_containers)
        else:
            print("Container exists, ensuring it's running...")
            self.ensure_container_running()

        # Set up system-level cleanup if requested
        if auto_cleanup_days > 0:
            print(f"Setting up auto-cleanup after {auto_cleanup_days} days...")
            self.schedule_system_cleanup(auto_cleanup_days)
        else:
            print("Auto-cleanup not requested")

        # First, start symbol server in the container
        print("\nStarting symbol server...")
        self.start_symbol_server_in_container(rpms, vendor_files, yocto_manifest)

        # If no coredump file provided, we're done (container is running)
        if coredump_file is None:
            print("No coredump file provided. Container is ready for interactive use.")
            return None

        # Then run gdb-multiarch with the coredump file
        print(f"\n===== STARTING GDB ANALYSIS =====")
        print(f"Starting GDB analysis of {coredump_file}...")

        # Get the absolute path to the coredump file
        coredump_path = os.path.abspath(coredump_file)
        print(f"Absolute coredump path: {coredump_path}")

        # Run gdb-multiarch with the command directly
        gdb_cmd = [
            '/bin/bash', '-c',
            f'gdb-multiarch -ex "thread apply all bt" -c "{coredump_path}"'
        ]
        print(f"GDB command: {gdb_cmd}")

        return self.run_command_in_container(gdb_cmd, self.script_dir)

    def start_symbol_server_in_container(self, rpms=None, vendor_files=None, yocto_manifest=None):
        """Start the debuginfod symbol server inside the container"""
        print("\n===== STARTING SYMBOL SERVER =====")
        print("Starting symbol server...")

        # First ensure any existing debuginfod processes are terminated
        print("Stopping any existing debuginfod processes...")
        kill_result = self.run_command_in_container([
            '/bin/bash', '-c',
            "pgrep debuginfod && pkill debuginfod || true"
        ])
        print(f"Debuginfod kill command result: {kill_result.returncode}")

        # Create the debuginfod command
        print("Creating debuginfod command...")
        debuginfod_cmd = self.create_debuginfod_command(rpms, vendor_files, yocto_manifest)

        # Run the debuginfod server in the container
        print(f"Starting debuginfod with command: {debuginfod_cmd}")
        server_result = self.run_command_in_container([
            '/bin/bash', '-c',
            f"DEBUGINFOD_URLS= {debuginfod_cmd} >/dev/null 2>&1 &"
        ])
        print(f"Debuginfod start command result: {server_result.returncode}")

        # Give the symbol server a moment to start
        print("Waiting for symbol server to initialize...")
        time.sleep(2)
        
        # Check if debuginfod is running
        check_result = self.run_command_in_container([
            '/bin/bash', '-c',
            "pgrep debuginfod || echo 'Not running'"
        ])
        print(f"Debuginfod process check: {check_result.stdout.strip()}")

    def create_debuginfod_command(self, rpms=None, vendor_files=None, yocto_manifest=None):
        """Create the debuginfod command with all the appropriate flags"""
        print("\n===== CREATING DEBUGINFOD COMMAND =====")
        
        # Base command with default paths - use config directory for debuginfod.sqlite
        cmd = f"debuginfod -d {self.debuginfod_db_path} -L -R rpms/ -F vendor/"
        print(f"Base debuginfod command: {cmd}")

        # Add additional RPM directories if specified
        if rpms:
            print(f"Adding RPM directories: {rpms}")
            for rpm_path in rpms:
                cmd += f" -R {rpm_path}"
                print(f"Added RPM path: {rpm_path}")

        # Add additional vendor files if specified
        if vendor_files:
            print(f"Adding vendor files: {vendor_files}")
            for vendor_path in vendor_files:
                cmd += f" -F {vendor_path}"
                print(f"Added vendor path: {vendor_path}")

        # Add yocto manifest if specified
        yocto_path = f"{yocto_manifest}/{self.tier}/{self.yocto_rpm_deploy_postfix}" if yocto_manifest else None
        if yocto_path and os.path.isdir(yocto_path):
            print(f"Adding Yocto manifest: {yocto_path}")
            cmd += f" -R {yocto_path}"
        elif yocto_manifest:
            print(f"WARNING: Yocto manifest path not found: {yocto_path}")

        print(f"Final debuginfod command: {cmd}")
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

    def install_heaptrack(self):
        """Install heaptrack in the container"""
        print("\n===== HEAPTRACK INSTALLATION =====")
        print("Installing heaptrack...")
        heaptrack_url = "https://github.com/KDE/heaptrack/releases/download/v1.5.0/heaptrack-1.5.0-Linux.deb"
        
        commands = [
            f'cd /tmp && wget -q -O heaptrack.deb {heaptrack_url}',
            'dpkg -i heaptrack.deb || (apt-get update && apt-get -f install -y && dpkg -i heaptrack.deb)',
            'rm -f heaptrack.deb'
        ]
        
        for i, cmd in enumerate(commands):
            print(f"Executing heaptrack installation step {i+1}/3: {cmd}")
            result = self.run_command_in_container(['sudo', 'bash', '-c', cmd])
            if result.returncode != 0:
                print(f"ERROR: heaptrack 설치 중 오류 발생: {cmd}")
                print(f"Return code: {result.returncode}")
                return False
            print(f"Step {i+1} completed successfully")
        
        print("heaptrack 설치 완료")
        
        # 설치 확인
        print("Verifying heaptrack installation...")
        check_cmd = "which heaptrack"
        result = self.run_command_in_container(['bash', '-c', check_cmd])
        if result.returncode == 0:
            print("heaptrack found in PATH")
        else:
            print("WARNING: heaptrack command not found in PATH")
        
        return True


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
    print("\n===== CRASHCHECKER STARTED =====")
    print(f"Script path: {os.path.abspath(__file__)}")
    print(f"Python version: {sys.version}")
    print(f"Current user: {pwd.getpwuid(os.getuid()).pw_name} (uid={os.getuid()})")
    print(f"Current directory: {os.getcwd()}")
    
    if os.geteuid() == 0:
        print("ERROR: Please do not run as root.")
        sys.exit(1)

    args = parse_args()
    print("\n===== COMMAND LINE ARGUMENTS =====")
    for arg, value in vars(args).items():
        print(f"{arg}: {value}")

    # Initialize Docker manager
    print("\n===== INITIALIZING DOCKER MANAGER =====")
    docker_manager = DockerManager()
    if args.tier:
        print(f"Setting tier to: {args.tier}")
        docker_manager.tier = args.tier

    # Use local build if specified
    if args.local_build:
        print("Using local build instead of pre-built image")
        docker_manager.use_prebuilt_image = False
        docker_manager.docker_image = docker_manager.local_docker_image
        print(f"Local docker image: {docker_manager.docker_image}")

    # Ensure rpms and vendor directories exist
    print("\n===== CHECKING DIRECTORIES =====")
    docker_manager.setup_rpms_and_vendor_dirs()

    # If no coredump file is provided, just start the container in interactive mode
    if args.coredump_file is None or args.interactive:
        print("\n===== INTERACTIVE MODE =====")
        print("No coredump file provided or interactive mode specified. Starting container shell...")
        if not docker_manager.container_exists() or args.new_container:
            print("Container needs to be created or recreated.")
            docker_manager.create_container(force_new=False, remove_all=args.new_container)
        else:
            print("Container exists, ensuring it's running...")
            docker_manager.ensure_container_running()

        # Start an interactive shell in the container
        print("\n===== STARTING INTERACTIVE SHELL =====")
        print(f"Connecting to container {docker_manager.docker_container}...")
        shell_cmd = [
            'docker', 'exec', '-it', docker_manager.docker_container, '/bin/bash'
        ]
        print(f"Command: {' '.join(shell_cmd)}")
        subprocess.run(shell_cmd)
        print("\n===== INTERACTIVE SHELL EXITED =====")
    else:
        # Analyze the coredump file
        print("\n===== COREDUMP ANALYSIS MODE =====")
        print(f"Analyzing coredump file: {args.coredump_file}")
        analysis_result = docker_manager.analyze_coredump(
            args.coredump_file,
            force_new_container=False,
            remove_all_containers=args.new_container,
            auto_cleanup_days=args.auto_remove_days,
            rpms=args.rpms,
            vendor_files=args.vendor,
            yocto_manifest=args.yocto_manifest
        )
        print("\n===== COREDUMP ANALYSIS COMPLETE =====")
        if analysis_result:
            print(f"GDB analysis completed with return code: {analysis_result.returncode}")
        else:
            print("No analysis result returned.")

    print("\n===== CRASHCHECKER FINISHED =====")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n===== CRASHCHECKER INTERRUPTED =====")
        print("Received keyboard interrupt. Exiting...")
        sys.exit(130)
    except Exception as e:
        print("\n===== CRASHCHECKER ERROR =====")
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)