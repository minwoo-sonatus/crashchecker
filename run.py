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

GITHUB_REPO = os.environ.get("GITHUB_REPO", "minwoo-sonatus/crashchecker")
CONTAINER_IMAGE_URL = f"ghcr.io/{GITHUB_REPO}/dbg-container:latest"

# ------------------------------------------------------------------------------
# Embedded Dockerfile
# ------------------------------------------------------------------------------
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
# ------------------------------------------------------------------------------

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
            cmd = ['docker', 'ps', '-a', '--filter', f"name={self.container_prefix}", '--format', '{{.Names}}']
            print(f"Running command for existing containers: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
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
                
                # # Install heaptrack if this is a new container
                # print("\n===== INSTALLING HEAPTRACK =====")
                # self.install_heaptrack()
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

    def run_command_in_container(self, command, working_dir=None, interactive=False):
        """Run command inside the container
        
        Args:
            command: 실행할 명령어 (문자열 또는 리스트)
            working_dir: 작업 디렉토리 경로
            interactive: True인 경우 사용자 입력을 기다리는 대화형 명령어로 실행
        """
        print(f"\n===== RUNNING COMMAND IN CONTAINER =====")
        
        cmd = ['docker', 'exec']

        if working_dir:
            print(f"Working directory: {working_dir}")
            cmd.extend(['-w', working_dir])

        if interactive:
            print("Running in interactive mode")
            cmd.append('-it')
        else:
            print("Running in non-interactive mode")
        
        cmd.append(self.docker_container)
        cmd.extend(command if isinstance(command, list) else command.split())
        
        cmd_str = ' '.join(cmd)
        print(f"Executing command: {cmd_str}")
        
        if interactive:
            # 대화형 명령어는 직접 실행하고 결과를 캡처
            print("Interactive command - output will be shown directly")
            try:
                result = subprocess.run(cmd)
                return result
            except KeyboardInterrupt:
                print("Command was interrupted by user")
                # KeyboardInterrupt가 발생해도 객체를 반환
                return subprocess.CompletedProcess(cmd, 130, stdout=None, stderr=None)
        else:
            # 비대화형 명령어는 출력을 캡처하여 반환
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            print(f"Command finished with return code: {result.returncode}")
            
            # stdout 처리 (None인 경우 대비)
            if hasattr(result, 'stdout') and result.stdout is not None:
                if result.stdout:
                    print(f"Command stdout (truncated if large):\n{result.stdout[:1000]}")
                    if len(result.stdout) > 1000:
                        print(f"... (output truncated, total length: {len(result.stdout)} bytes)")
            else:
                print("Command stdout: None")
            
            # stderr 처리 (None인 경우 대비)
            if hasattr(result, 'stderr') and result.stderr is not None:
                if result.stderr:
                    print(f"Command stderr (truncated if large):\n{result.stderr[:1000]}")
                    if len(result.stderr) > 1000:
                        print(f"... (error output truncated, total length: {len(result.stderr)} bytes)")
            else:
                print("Command stderr: None")
            
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
            f'gdb-multiarch -ex "set context-max-threads 100" -ex "thread apply all bt" -c "{coredump_path}"'
        ]
        print(f"GDB command: {gdb_cmd}")

        # GDB는 사용자 입력을 기다릴 수 있으므로 대화형 모드로 실행
        print("Running GDB in interactive mode - you can interact with GDB")
        return self.run_command_in_container(gdb_cmd, self.script_dir, interactive=True)

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
        # 로그 파일 경로 설정
        debuginfod_log_file = "/tmp/debuginfod.log"
        debuginfod_cmd = self.create_debuginfod_command(rpms, vendor_files, yocto_manifest)
        
        # 로그 파일로 출력을 리디렉션하도록 수정
        cmd_with_log = f"{debuginfod_cmd} > {debuginfod_log_file} 2>&1 &"

        # Run the debuginfod server in the container
        print(f"Starting debuginfod with command: {cmd_with_log}")
        server_result = self.run_command_in_container([
            '/bin/bash', '-c',
            f"DEBUGINFOD_URLS= {cmd_with_log}"
        ])
        print(f"Debuginfod start command result: {server_result.returncode}")

        # Check if debuginfod is running
        check_result = self.run_command_in_container([
            '/bin/bash', '-c',
            "pgrep debuginfod || echo 'Not running'"
        ])
        if check_result.returncode == 0:
            # stdout가 None이 아닌 경우에만 strip() 호출
            if hasattr(check_result, 'stdout') and check_result.stdout is not None:
                print(f"Debuginfod process check: {check_result.stdout.strip()}")
                
                # 인덱싱이 완료될 때까지 기다림
                print("\n===== WAITING FOR DEBUGINFOD INDEXING =====")
                print("Waiting for debuginfod to finish indexing...")
                print("This may take some time depending on the amount of data to index.")
                print("Press Ctrl+C to stop waiting and continue (debuginfod will still run in background).")
                
                try:
                    # 초기 대기 시간
                    time.sleep(3)
                    
                    # 인덱싱 완료를 확인하는 메시지들
                    completion_indicators = [
                        "Finished building scanners for",
                        "ready to serve requests",
                        "Connection from",
                        "Serving request",
                        "Finished initial database organization"
                    ]
                    
                    # 인덱싱 진행 중을 나타내는 메시지들
                    progress_indicators = [
                        "Scanning",
                        "traverse_elf",
                        "Processing",
                        "Indexing",
                        "Thread",
                        "archive"
                    ]
                    
                    max_wait_time = 300  # 최대 5분 대기
                    start_time = time.time()
                    last_line = ""
                    last_status_time = time.time()
                    indexing_complete = False
                    rpm_count = 0
                    indexed_count = 0
                    
                    print("Progress indicators: ", end="")
                    sys.stdout.flush()
                    
                    while time.time() - start_time < max_wait_time:
                        # 로그 파일의 마지막 20줄 확인
                        log_check = self.run_command_in_container([
                            '/bin/bash', '-c',
                            f"tail -20 {debuginfod_log_file} 2>/dev/null || echo 'Log file not found'"
                        ])
                        
                        if log_check.returncode == 0 and log_check.stdout:
                            # 로그 출력
                            log_lines = log_check.stdout.splitlines()
                            
                            # RPM 카운트 업데이트
                            for line in log_lines:
                                if "rpm" in line.lower() and any(ind in line for ind in progress_indicators):
                                    rpm_count += 1
                                if any(ind in line for ind in completion_indicators):
                                    indexed_count += 1
                            
                            # 마지막 줄 출력 (이전과 다른 경우)
                            if log_lines and log_lines[-1] != last_line:
                                last_line = log_lines[-1]
                                
                                # 진행 상황을 보여주는 라인인 경우 출력
                                if any(ind in last_line for ind in progress_indicators + completion_indicators):
                                    # 3초마다 또는 완료 메시지가 있을 때 상태 업데이트
                                    if time.time() - last_status_time > 3 or any(ind in last_line for ind in completion_indicators):
                                        last_status_time = time.time()
                                        elapsed = int(time.time() - start_time)
                                        print(f"\rIndexing: {rpm_count} RPMs processed, {indexed_count} completed ({elapsed}s elapsed) ", end="")
                                        sys.stdout.flush()
                            
                            # 인덱싱 완료 확인
                            for line in log_lines:
                                if any(ind in line for ind in completion_indicators):
                                    if rpm_count > 0 and indexed_count > 0:
                                        print(f"\nDebuginfod indexing seems complete! ({indexed_count}/{rpm_count} items processed)")
                                        indexing_complete = True
                                        break
                            
                            if indexing_complete:
                                break
                        
                        # 주기적으로 프로세스가 살아있는지 확인
                        if not self.is_debuginfod_running():
                            print("\nWARNING: Debuginfod process is no longer running!")
                            break
                        
                        # 진행 중인 것을 보여주는 간단한 인디케이터
                        if time.time() - last_status_time > 10:
                            print(".", end="")
                            sys.stdout.flush()
                        
                        # 잠시 대기
                        time.sleep(1)
                    
                    if not indexing_complete and time.time() - start_time >= max_wait_time:
                        print("\nWaited maximum time for indexing. Continuing anyway...")
                        print(f"Processed approximately {rpm_count} RPMs so far.")
                        print("Debuginfod will continue indexing in the background.")
                        
                        # 마지막 로그 몇 줄 출력
                        print("\nLast few lines of debuginfod log:")
                        tail_result = self.run_command_in_container([
                            '/bin/bash', '-c',
                            f"tail -5 {debuginfod_log_file}"
                        ])
                        if tail_result.returncode == 0 and tail_result.stdout:
                            print(tail_result.stdout)
                
                except KeyboardInterrupt:
                    print("\nUser interrupted waiting. Continuing...")
                    print("Debuginfod will continue indexing in the background.")
            else:
                print("Debuginfod process check: Unknown (stdout is None)")
        else:
            print(f"Debuginfod process check failed with return code: {check_result.returncode}")
    
    def is_debuginfod_running(self):
        """Check if debuginfod is still running"""
        check_result = self.run_command_in_container([
            '/bin/bash', '-c',
            "pgrep debuginfod > /dev/null && echo 'yes' || echo 'no'"
        ])
        
        if check_result.returncode == 0 and check_result.stdout:
            return check_result.stdout.strip() == 'yes'
        return False

    def create_debuginfod_command(self, rpms=None, vendor_files=None, yocto_manifest=None):
        """Create the debuginfod command with all the appropriate flags"""
        print("\n===== CREATING DEBUGINFOD COMMAND =====")
        
        # Base command with default paths - use config directory for debuginfod.sqlite
        # -v 옵션 추가하여 자세한 로그 출력
        cmd = f"debuginfod -v -d {self.debuginfod_db_path} -L -R rpms/ -F vendor/"
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
        
        success = True
        
        for i, cmd in enumerate(commands):
            print(f"Executing heaptrack installation step {i+1}/3: {cmd}")
            
            # sudo 명령어는 항상 대화형으로 처리
            if 'sudo' in cmd:
                print("Running with interactive mode (sudo command detected)")
                interactive_result = self.run_command_in_container(['sudo', 'bash', '-c', cmd], interactive=True)
                # 대화형 모드에서는 결과가 None일 수 있으므로 특별한 처리 필요
                if interactive_result is None or interactive_result.returncode != 0:
                    print(f"ERROR: heaptrack 설치 중 오류 발생: {cmd}")
                    if interactive_result:
                        print(f"Return code: {interactive_result.returncode}")
                    success = False
                    break
            else:
                # 비대화형 명령 실행
                result = self.run_command_in_container(['bash', '-c', cmd])
                if result.returncode != 0:
                    print(f"ERROR: heaptrack 설치 중 오류 발생: {cmd}")
                    print(f"Return code: {result.returncode}")
                    success = False
                    break
            
            print(f"Step {i+1} completed successfully")
        
        if success:
            print("heaptrack 설치 완료")
            
            # 설치 확인
            print("Verifying heaptrack installation...")
            check_cmd = "which heaptrack"
            result = self.run_command_in_container(['bash', '-c', check_cmd])
            if result.returncode == 0:
                print("heaptrack found in PATH")
            else:
                print("WARNING: heaptrack command not found in PATH")
        else:
            print("heaptrack 설치 실패")
        
        return success


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
        
        # 대화형 모드로 bash 실행
        bash_cmd = ['/bin/bash']
        docker_manager.run_command_in_container(bash_cmd, interactive=True)
        
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