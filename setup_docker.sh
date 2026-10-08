#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: ./setup_docker.sh [--image IMAGE] [--name CONTAINER]

Build the Docker image, mount this repository at /root/HarnessMinimizer,
and install the supplied benchmarks' additional packages in the container.
Requires Linux x86-64 and access to a local Docker daemon.

  --image IMAGE     Image to build (default: harnessminimizer:latest)
  --name CONTAINER  Container to create (default: harnessminimizer-eval)
  -h, --help        Show this help

An existing container is left untouched. Choose another name to create a
new container. Benchmark data must be supplied separately under benchmark/.
EOF
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

print_command() {
    printf '  '
    printf '%q ' "$@"
    printf '\n'
}

image_name=harnessminimizer:latest
container_name=harnessminimizer-eval
while (($#)); do
    case "$1" in
        --image|--name)
            option="$1"
            if (($# < 2)) || [[ -z "$2" || "$2" == -* ]]; then
                fail "$option requires a value. Use --help for usage."
            fi
            if [[ "$option" == --image ]]; then
                image_name="$2"
            else
                container_name="$2"
            fi
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown argument: $1. Use --help for usage."
            ;;
    esac
done

[[ "$container_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || fail "Invalid container name: $container_name"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
container_workspace=/root/HarnessMinimizer
louis_tablepath="$container_workspace/benchmark/library-bug/liblouis-1/build/sanitizer/share/liblouis/tables"
[[ -f "$repo_dir/Dockerfile" ]] || fail "Dockerfile is missing beside this script."
command -v docker >/dev/null 2>&1 || fail "Docker is not installed or is not on PATH."

step='checking access to Docker'
container_requested=false
on_error() {
    local status=$?
    printf 'Error: %s failed (exit %s).\n' "$step" "$status" >&2
    if [[ "$container_requested" == true ]]; then
        printf 'Any container created has been preserved for diagnosis. Inspect it with:\n' >&2
        print_command docker container inspect "$container_name" >&2
        print_command docker logs "$container_name" >&2
    fi
    exit "$status"
}
trap on_error ERR

docker info >/dev/null
if docker container inspect "$container_name" >/dev/null 2>&1; then
    printf 'Container %q already exists and has been left untouched.\n' "$container_name" >&2
    printf 'To start and enter the existing container:\n' >&2
    print_command docker start "$container_name" >&2
    print_command docker exec -it --workdir "$container_workspace" "$container_name" bash >&2
    printf 'To build an image and create a separate container:\n' >&2
    print_command "$repo_dir/setup_docker.sh" --image "$image_name" --name "${container_name}-new" >&2
    exit 1
fi

step='building the Docker image'
printf 'Building image %s from %s/Dockerfile\n' "$image_name" "$repo_dir"
docker build --file "$repo_dir/Dockerfile" --tag "$image_name" "$repo_dir"

step='creating and starting the container'
printf 'Creating container %s with workspace %s\n' "$container_name" "$repo_dir"
# Docker parses --mount as CSV, so also escape quotes inside its source field.
mount_source="${repo_dir//\"/\"\"}"
container_requested=true
docker run --detach --name "$container_name" --init \
    --mount "type=bind,\"source=$mount_source\",target=$container_workspace" \
    --workdir "$container_workspace" \
    --env "LOUIS_TABLEPATH=$louis_tablepath" \
    "$image_name" sleep infinity

step='updating the container package index'
docker exec --user 0 --env DEBIAN_FRONTEND=noninteractive "$container_name" \
    apt-get update

step='installing the benchmark dependencies in the container'
benchmark_packages=(
    libzstd-dev libjbig-dev libjpeg-dev
    libnl-genl-3-dev libnl-3-dev libdbus-1-dev libexpat1-dev
)
docker exec --user 0 --env DEBIAN_FRONTEND=noninteractive "$container_name" \
    apt-get install -y --no-install-recommends "${benchmark_packages[@]}"

printf '\nContainer %s is ready. Continue installation inside it:\n' "$container_name"
print_command docker exec -it "$container_name" bash
if [[ ! -d "$repo_dir/benchmark/library-bug/liblouis-1/build/sanitizer/share/liblouis/tables" ]]; then
    printf 'Before running liblouis cases, supply the benchmark data containing:\n  %s\n' "$louis_tablepath"
fi
