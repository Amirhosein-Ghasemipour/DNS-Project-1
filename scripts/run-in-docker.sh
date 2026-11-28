#!/usr/bin/env bash
# Run the whole validation pipeline in containers (the spec's isolated
# execution environment: "all tests run in an isolated environment such as a
# container with resource limits, on authorized programs").
#
# Two modes:
#
#   scripts/run-in-docker.sh                 (default, recommended)
#       Runs patchcheck on the host and forces --backend docker, so EVERY
#       build and every test execution happens in its own hardened container
#       built from docker/Dockerfile: --network=none, --read-only root
#       filesystem, --cap-drop=ALL, no-new-privileges, non-root user and
#       cgroup memory/CPU/PID limits (patchcheck/sandbox.py, _execute_docker).
#       This is the strongest envelope the tool provides and matches the
#       requirement literally.
#
#   scripts/run-in-docker.sh --inside [evaluate.py args...]
#       Runs the ENTIRE pipeline inside one resource-limited container
#       (--network=none, --cap-drop=ALL, cgroup limits). Inside, patchcheck's
#       own backend probe usually still resolves to restricted (Docker's
#       default seccomp profile denies user namespaces), which is correct:
#       the outer container is the isolation layer and the report records
#       exactly what ran.
#
# Extra arguments (after the optional --inside) are forwarded to
# scripts/evaluate.py, e.g. --only cjson-correct or --targets record-reader.
# The output directory is chosen here (artifacts/evaluation-docker-<ts>) and
# must not exist beforehand.
#
# Image override: PATCHCHECK_IMAGE=name:tag ./scripts/run-in-docker.sh

set -euo pipefail
cd "$(dirname "$0")/.."

echo "== run-in-docker: checking Docker availability =="

IMAGE="${PATCHCHECK_IMAGE:-patchcheck-toolchain:1}"
PLATFORM=linux/amd64
INSIDE=0
if [[ "${1:-}" == "--inside" ]]; then
    INSIDE=1
    shift
fi

# Distinguish the three usual failure modes instead of one vague message:
# (1) Docker CLI missing entirely, (2) daemon installed but not running,
# (3) daemon running but the socket denies this user.
diagnose_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        cat >&2 <<'EOF'
error: the Docker CLI is not installed on this machine.

  Windows/macOS : install Docker Desktop and launch it; wait until its icon
                  shows "running", then reopen the terminal.
                  https://docs.docker.com/get-docker/
  WSL2          : install Docker Desktop on Windows, then enable
                  Settings -> Resources -> WSL Integration for this distro.
  Linux         : sudo apt-get install -y docker.io
                    (or the official engine: docs.docker.com/engine/install)
                  sudo systemctl enable --now docker
                  sudo usermod -aG docker "$USER"   # log out and back in
Check:            docker --version
EOF
        exit 30
    fi
    if ! docker info >/dev/null 2>&1; then
        # Capture the daemon's complaint without letting the script die
        # silently: under "set -euo pipefail", a failing pipeline inside a
        # plain variable assignment aborts the script before the message
        # below can print (the bug that produced a completely silent exit
        # when the CLI existed but the daemon was down). Every stage is
        # therefore forced to succeed; only the text is wanted.
        detail="$({ docker info 2>&1 || true; } | grep -v '^[[:space:]]*$' | tail -2 || true)"
        cat >&2 <<EOF
error: the Docker CLI is installed, but the daemon is not reachable.

    ${detail:-docker info failed with no output}

  Windows/macOS : start Docker Desktop and wait until its status is
                  "running" (green), then re-run this script.
  WSL2          : Docker Desktop must be running on the Windows side and
                  WSL Integration enabled for this distro
                  (Settings -> Resources -> WSL Integration).
  Linux         : sudo systemctl start docker     (or: sudo service docker start)
  permissions   : if the message says "permission denied ... /var/run/docker.sock",
                  run: sudo usermod -aG docker "\$USER"  and log out and back in.
  DOCKER_HOST   : if this variable is set, unset it or point it at a
                  reachable daemon.
Verify with:      docker run --rm hello-world
EOF
        exit 30
    fi
}
diagnose_docker

# A previous run with sudo leaves targets/ and artifacts/ root-owned; a later
# non-root run would then die deep inside preparation with "permission denied"
# instead of a diagnosis. Detect that state here, where the fix can be printed.
# (Running WITH sudo is fine: the docker backend hands each root-owned build
# directory to the container's non-root user before its build.)
if [[ $EUID -ne 0 && -n "$(find targets artifacts -user root -print -quit 2>/dev/null)" ]]; then
    cat >&2 <<EOF
error: 'targets/' or 'artifacts/' contains root-owned files from an earlier
'sudo' run, but this run is not root; host-side preparation would fail with
"permission denied".

  Either re-run with sudo (recommended while your user is not in the docker
  group), or take ownership once and stay without sudo:

      sudo chown -R "$(id -u):$(id -g)" targets artifacts
EOF
    exit 30
fi

OUT="artifacts/evaluation-docker-$(date +%Y%m%d-%H%M%S)"
if [[ -e "$OUT" ]]; then
    echo "error: output directory already exists: $OUT" >&2
    exit 30
fi

echo "== [1/3] building the toolchain image (${IMAGE}, ${PLATFORM}) =="
# evaluate.py's docker backend expects the default tag; an override via
# PATCHCHECK_IMAGE gets an additional tag on the same image (--image is not
# an evaluate.py option; only `run`/`replay` accept it).
TAGS=(-t patchcheck-toolchain:1)
if [[ "$IMAGE" != "patchcheck-toolchain:1" ]]; then
    TAGS+=(-t "$IMAGE")
fi
docker build --platform="${PLATFORM}" "${TAGS[@]}" docker/

if [[ "$INSIDE" == 1 ]]; then
    echo "== [2/3] running restore + prepare + evaluate inside one container =="
    echo "        outer isolation: --network=none --cap-drop=ALL --memory=4g --cpus=2 --pids-limit=256"
    docker run --rm --platform="${PLATFORM}" \
        --network=none --cap-drop=ALL --security-opt=no-new-privileges:true \
        --memory=4g --memory-swap=4g --cpus=2 --pids-limit=256 --ulimit=core=0:0 \
        --tmpfs=/tmp:rw,nosuid,nodev,size=512m \
        --user="$(id -u):$(id -g)" \
        --mount type=bind,source="$(pwd)",target=/work \
        "${IMAGE}" bash -c '
            set -e
            python3 scripts/restore_sources.py
            python3 scripts/prepare_examples.py
            python3 scripts/evaluate.py --output "$1" "${@:2}"
        ' inner "$OUT" "$@"
else
    echo "== [2/3] preparing pinned sources and test inputs (host side, idempotent) =="
    python3 scripts/restore_sources.py
    python3 scripts/prepare_examples.py

    echo "== [3/3] evaluating: every build and execution in its own container =="
    python3 scripts/evaluate.py --backend docker --output "${OUT}" "$@"
fi

echo
echo "Done. Open the results in a browser:  ${OUT}/evaluation.html"
echo "Per-scenario evidence: ${OUT}/<scenario>/summary.txt (human) and"
echo "${OUT}/<scenario>/report.json (structured; records the sandbox identity that ran)."

if [[ $EUID -eq 0 && -n "${SUDO_UID:-}" ]]; then
    echo
    echo "Note: this run used sudo, so artifacts/ and targets/ are root-owned."
    echo "      To hand them back to your user:"
    echo "        sudo chown -R \"${SUDO_UID}:${SUDO_GID:-${SUDO_UID}}\" targets artifacts"
fi
