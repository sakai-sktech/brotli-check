#!/usr/bin/env bats
# C14: where docker and podman connect (issue #6, docs/design.md 10.20). The containers are
# listed and counted whatever the connection, and the connection is reported with them; the
# check script runs inside them only through a unix socket on this host. Stopped containers and
# images are counted and never looked inside; their number goes to "Not scanned" (issue #8,
# docs/design.md 10.24).

load test_helper

setup() {
  load_libs
  setup_fakebin
  D="$BATS_TEST_TMPDIR/docker"
  mkdir -p "$D"
  export BCC_FAKE_DOCKER=$D
  BCC_CONTAINERS=1
  BCC_INSPECT_CONTAINERS=1
  # A fake docker that settles its connection the way docker 29.9 was seen to (2026-11-04):
  # --context NAME, then DOCKER_HOST, then DOCKER_CONTEXT, then the current context of its
  # configuration ($D/current), then the default socket. "context inspect" with no name answers
  # for that context; $D/switch-to, if present, becomes the current context right after it, as if
  # "docker context use" ran in another terminal. Every call is logged with where it went.
  # "ps -a" lists the running container and the IDs in $D/stopped; $D/psa-fails and
  # $D/images-fails make those calls fail, $D/no-running leaves ps empty.
  cat >"$FAKEBIN/docker" <<'EOS'
#!/bin/sh
D=$BCC_FAKE_DOCKER
all="$*"
if [ "$1" = --context ]; then ctx=$2; shift 2
elif [ -n "${DOCKER_HOST:-}" ]; then ctx=default
elif [ -n "${DOCKER_CONTEXT:-}" ]; then ctx=$DOCKER_CONTEXT
elif [ -s "$D/current" ]; then ctx=$(cat "$D/current")
else ctx=default; fi
if [ "$ctx" = default ]; then host=${DOCKER_HOST:-unix:///var/run/docker.sock}
elif [ -f "$D/ctx-$ctx" ]; then host=$(cat "$D/ctx-$ctx")
else echo "context \"$ctx\": context not found" >&2; exit 1; fi
echo "$host | $all" >>"$D/log"
case $1 in
  context)
    [ -f "$D/no-context" ] && { echo "docker: 'context' is not a docker command." >&2; exit 1; }
    printf '%s %s\n' "$ctx" "$host"
    if [ -f "$D/switch-to" ]; then cp "$D/switch-to" "$D/current"; fi
    ;;
  ps)
    [ -f "$D/ps-fails" ] && { echo "Cannot connect to the Docker daemon at $host." >&2; exit 1; }
    if [ "$2" = -a ]; then
      [ -f "$D/psa-fails" ] && { echo "error during connect" >&2; exit 1; }
      [ -f "$D/no-running" ] || printf '0123abcd\n'
      if [ -f "$D/stopped" ]; then cat "$D/stopped"; fi
    elif [ ! -f "$D/no-running" ]; then
      printf '0123abcd\timg:1\tweb\n'
    fi
    ;;
  images)
    [ -f "$D/images-fails" ] && { echo "error during connect" >&2; exit 1; }
    printf 'sha256:aa\nsha256:bb\nsha256:aa\n'
    ;;
  exec) printf 'OS\tdebian\ttrixie\t\nNODE\t/usr/local/bin/node\tv22.23.3\nEND\n' ;;
esac
EOS
  chmod +x "$FAKEBIN/docker"
}

info_text() { printf '%s\n' ${BCC_INFO[@]+"${BCC_INFO[@]}"}; }
# bats does not fail a test on "! cmd"; these do.
ran_inside() { grep -q -- "$1" "$2"; }
nothing_ran_inside() { if grep -q -- "$1" "$2"; then return 1; fi; }
skipped_text() { printf '%s\n' ${BCC_SKIPPED[@]+"${BCC_SKIPPED[@]}"}; }

# A fake podman; docker is then hidden, since docker comes first and the host may have a real one.
fake_podman() {
  cat >"$FAKEBIN/podman" <<EOS
#!/bin/sh
echo "\$*" >>"$D/podman-log"
case \$1 in
  info) $1 ;;
  ps) if [ "\$2" = -a ]; then printf '0123abcd\nfeed0001\n'; else printf '0123abcd\timg:1\tweb\n'; fi ;;
  images) printf 'sha256:aa\n' ;;
  exec) printf 'OS\tdebian\ttrixie\t\nNODE\t/usr/local/bin/node\tv22.23.3\nEND\n' ;;
esac
EOS
  chmod +x "$FAKEBIN/podman"
  rm -f "$FAKEBIN/docker"
  bcc_have() { [[ $1 != docker ]] && command -v -- "$1" >/dev/null 2>&1; }
}

@test "C14: DOCKER_HOST to another host: listed and counted with the connection, nothing runs inside" {
  DOCKER_HOST=ssh://admin@other-host DOCKER_CONTEXT=prod bcc_check_c14
  run info_text
  [[ $output == *"C14"$'\t'"Connection of docker: ssh://admin@other-host. This is not a unix socket on this host"* ]]
  [[ $output == *"C14"$'\t'"docker: 1 running containers, 0 stopped containers, 2 images."* ]]
  [[ $output == *"C14"$'\t'"Container web (img:1) was not inspected (see the connection of the engine above)."* ]]
  run skipped_text
  # Stopped containers and images are not looked inside on any connection (issue #8).
  [ "$output" = "C14 (images)"$'\t'"inside of images (2 counted): images are not looked inside, with or without --inspect-containers"$'\n'"C14"$'\t'"inside of running containers: docker connects to ssh://admin@other-host, not to a unix socket on this host, so nothing was run inside them" ]
  # The list is that host's, and nothing was run inside its containers.
  grep -q '^ssh://admin@other-host | --context default ps ' "$D/log"
  nothing_ran_inside ' exec ' "$D/log"
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
}

@test "C14: DOCKER_CONTEXT naming a tcp context: the same, and every call stays on that context" {
  printf 'tcp://prod.example:2376\n' >"$D/ctx-prod"
  DOCKER_CONTEXT=prod bcc_check_c14
  run info_text
  [[ $output == *"Connection of docker: tcp://prod.example:2376. This is not a unix socket on this host"* ]]
  [[ $output == *"docker: 1 running containers, 0 stopped containers, 2 images."* ]]
  run skipped_text
  [[ $output == *"docker connects to tcp://prod.example:2376, not to a unix socket on this host"* ]]
  grep -q '^tcp://prod.example:2376 | --context prod ps ' "$D/log"
  grep -q '^tcp://prod.example:2376 | --context prod images -q' "$D/log"
  nothing_ran_inside ' exec ' "$D/log"
}

@test "C14: tcp://localhost is not taken for this host (it may be a tunnel to another one)" {
  printf 'lo\n' >"$D/current"
  printf 'tcp://localhost:2375\n' >"$D/ctx-lo"
  bcc_check_c14
  run info_text
  [[ $output == *"Connection of docker: tcp://localhost:2375. This is not a unix socket on this host"* ]]
  nothing_ran_inside ' exec ' "$D/log"
  [ "${#BCC_FINDINGS[@]}" -eq 0 ]
}

@test "C14: a unix socket on this host: inspected as before, through the context that was checked" {
  bcc_check_c14
  run info_text
  [[ $output == *"C14"$'\t'"Connection of docker: unix:///var/run/docker.sock (a unix socket on this host)."* ]]
  [[ $output == *"docker: 1 running containers, 0 stopped containers, 2 images."* ]]
  [[ $output != *"was not inspected"* ]]
  run findings_brief
  [[ $output == *"VULNERABLE|C14|node|container web (img:1) /usr/local/bin/node|22.23.3"* ]]
  grep -q '^unix:///var/run/docker.sock | --context default exec 0123abcd sh -c ' "$D/log"
  # The images are only counted, also when the containers were looked inside (issue #8).
  run skipped_text
  [ "$output" = "C14 (images)"$'\t'"inside of images (2 counted): images are not looked inside, with or without --inspect-containers" ]
}

@test "C14: DOCKER_HOST naming a unix socket is this host too" {
  DOCKER_HOST=unix:///run/user/1000/docker.sock bcc_check_c14
  run info_text
  [[ $output == *"Connection of docker: unix:///run/user/1000/docker.sock (a unix socket on this host)."* ]]
  grep -q '^unix:///run/user/1000/docker.sock | --context default exec 0123abcd ' "$D/log"
}

@test "C14: a context switched during the scan does not move the scan to it" {
  printf 'desk\n' >"$D/current"
  printf 'unix:///home/u/.docker/desktop/docker.sock\n' >"$D/ctx-desk"
  printf 'tcp://prod.example:2376\n' >"$D/ctx-prod"
  printf 'prod\n' >"$D/switch-to"
  bcc_check_c14
  # Without --context, ps, ps -a, images and exec would have gone to prod.
  [ "$(grep -c '^unix:///home/u/.docker/desktop/docker.sock | --context desk ' "$D/log")" -eq 4 ]
  nothing_ran_inside '^tcp://' "$D/log"
  run findings_brief
  [[ $output == *"VULNERABLE|C14|node|container web (img:1) /usr/local/bin/node|22.23.3"* ]]
}

@test "C14: a docker that does not say where it connects: listed, nothing runs inside" {
  touch "$D/no-context"
  bcc_check_c14
  run info_text
  [[ $output == *"Connection of docker: not known (docker context inspect gave no answer)."* ]]
  [[ $output == *"docker: 1 running containers, 0 stopped containers, 2 images."* ]]
  [[ $output == *"Container web (img:1) was not inspected (see the connection of the engine above)."* ]]
  run skipped_text
  [[ $output == *"C14"$'\t'"inside of running containers: where docker connects is not known, so nothing was run inside them"* ]]
  nothing_ran_inside ' exec ' "$D/log"
}

@test "C14: the connection is reported also when docker then fails" {
  touch "$D/ps-fails"
  DOCKER_HOST=ssh://admin@other-host bcc_check_c14
  run info_text
  [[ $output == *"Connection of docker: ssh://admin@other-host."* ]]
  run skipped_text
  [[ $output == *"C14 docker"$'\t'"docker cannot be used by this user"* ]]
}

@test "C14: without --inspect-containers, a unix socket keeps the hint to use it" {
  BCC_INSPECT_CONTAINERS=0
  bcc_check_c14
  run info_text
  [[ $output == *"Connection of docker: unix:///var/run/docker.sock (a unix socket on this host)."* ]]
  [[ $output == *"Container web (img:1) was not inspected (use --inspect-containers)."* ]]
  run skipped_text
  [ "$output" = "C14 (images)"$'\t'"inside of images (2 counted): images are not looked inside, with or without --inspect-containers"$'\n'"C14"$'\t'"inside of running containers (use --inspect-containers)" ]
}

@test "C14: without --inspect-containers, another host gives the connection as the reason" {
  BCC_INSPECT_CONTAINERS=0
  DOCKER_HOST=tcp://203.0.113.5:2375 bcc_check_c14
  run info_text
  [[ $output == *"Container web (img:1) was not inspected (see the connection of the engine above)."* ]]
  [[ $output != *"use --inspect-containers"* ]]
  run skipped_text
  [[ $output == *"docker connects to tcp://203.0.113.5:2375, not to a unix socket on this host"* ]]
}

@test "C14: with --no-exec, another host still gives the connection as the reason" {
  BCC_NO_EXEC=1
  DOCKER_HOST=ssh://admin@other-host bcc_check_c14
  run skipped_text
  [[ $output == *"docker connects to ssh://admin@other-host"* ]]
  [[ $output != *"--no-exec"* ]]
}

@test "C14: podman with no service runs on this host: inspected" {
  fake_podman 'echo false'
  bcc_check_c14
  run info_text
  [[ $output == *"C14"$'\t'"Connection of podman: none. podman runs the containers on this host itself"* ]]
  [[ $output == *"podman: 1 running containers, 1 stopped containers, 1 images."* ]]
  run findings_brief
  [[ $output == *"VULNERABLE|C14|node|container web (img:1) /usr/local/bin/node|22.23.3"* ]]
  grep -q '^exec 0123abcd sh -c ' "$D/podman-log"
}

@test "C14: podman as a client of a service: listed, nothing runs inside" {
  fake_podman 'echo true'
  bcc_check_c14
  run info_text
  [[ $output == *"Connection of podman: a service (podman info), whose address podman does not state."* ]]
  [[ $output == *"podman: 1 running containers, 1 stopped containers, 1 images."* ]]
  [[ $output == *"Container web (img:1) was not inspected (see the connection of the engine above)."* ]]
  run skipped_text
  [[ $output == *"C14"$'\t'"inside of running containers: podman is a client of a service whose address it does not state"* ]]
  nothing_ran_inside '^exec ' "$D/podman-log"
}

@test "C14: podman that does not answer is not taken for this host" {
  fake_podman 'exit 125'
  bcc_check_c14
  run info_text
  [[ $output == *"Connection of podman: not known (podman info gave no answer)."* ]]
  run skipped_text
  [[ $output == *"where podman connects is not known"* ]]
  nothing_ran_inside '^exec ' "$D/podman-log"
}

@test "C14: only a docker answer of the expected shape is taken" {
  local answer
  for answer in "default" "default /var/run/docker.sock" "-x unix:///var/run/docker.sock" "default unix://"; do
    cat >"$FAKEBIN/docker" <<EOS
#!/bin/sh
case "\$*" in
  "context inspect "*) echo '$answer' ;;
  *" ps "*|"ps "*) printf '0123abcd\timg:1\tweb\n' ;;
  *exec*) echo exec >>"$D/log" ;;
esac
EOS
    bcc_init_findings
    bcc_check_c14
    [[ ${BCC_INFO[*]} == *"Connection of docker: not known"* || ${BCC_INFO[*]} == *"Connection of docker: unix://. This is not"* ]] || { echo "answer: $answer"; return 1; }
    [ ! -e "$D/log" ] || { echo "ran inside for: $answer"; return 1; }
  done
}

@test "C14: the connection lines exist in Japanese too" {
  BCC_LANG=ja
  DOCKER_HOST=ssh://admin@other-host bcc_check_c14
  run info_text
  [[ $output == *"docker の接続先: ssh://admin@other-host。このホストの unix ソケットではありません。"* ]]
  run skipped_text
  [[ $output == *"C14"$'\t'"実行中のコンテナの中（docker の接続先 ssh://admin@other-host はこのホストの unix ソケットではないため、中では何も実行していない）"* ]]
}

# --- stopped containers and images (issue #8, docs/design.md 10.24) ---------------------------

@test "C14: stopped containers are counted, never looked inside, and listed under Not scanned" {
  printf 'feed0001\nfeed0002\n' >"$D/stopped"
  bcc_check_c14
  run info_text
  [[ $output == *"C14"$'\t'"docker: 1 running containers, 2 stopped containers, 2 images."* ]]
  run skipped_text
  [ "$output" = "C14 (stopped containers)"$'\t'"inside of stopped containers (2 counted): nothing is run or read inside them, with or without --inspect-containers"$'\n'"C14 (images)"$'\t'"inside of images (2 counted): images are not looked inside, with or without --inspect-containers" ]
  # Counted through the context that was checked; only the running one was looked inside.
  grep -q '^unix:///var/run/docker.sock | --context default ps -a --format {{.ID}}$' "$D/log"
  [ "$(grep -c ' exec ' "$D/log")" -eq 1 ]
  nothing_ran_inside ' exec feed' "$D/log"
  run findings_brief
  [[ $output == *"VULNERABLE|C14|node|container web (img:1) /usr/local/bin/node|22.23.3"* ]]
  [[ $output != *"feed"* ]]
}

@test "C14: with no running container, stopped containers and images are still listed under Not scanned" {
  touch "$D/no-running"
  printf 'feed0001\n' >"$D/stopped"
  bcc_check_c14
  run info_text
  [[ $output == *"docker: 0 running containers, 1 stopped containers, 2 images."* ]]
  run skipped_text
  [[ $output == *"C14 (stopped containers)"$'\t'"inside of stopped containers (1 counted)"* ]]
  [[ $output == *"C14 (images)"$'\t'"inside of images (2 counted)"* ]]
  nothing_ran_inside ' exec ' "$D/log"
}

@test "C14: no stopped container and no image: nothing about them under Not scanned" {
  cat >"$FAKEBIN/docker" <<'EOS'
#!/bin/sh
[ "$1" = --context ] && shift 2
case "$1 $2" in
  "context inspect") echo 'default unix:///var/run/docker.sock' ;;
  "ps -a") printf '0123abcd\n' ;;
  ps*) printf '0123abcd\timg:1\tweb\n' ;;
  images*) : ;;
  exec*) printf 'OS\tdebian\ttrixie\t\nEND\n' ;;
esac
EOS
  bcc_check_c14
  run info_text
  [[ $output == *"docker: 1 running containers, 0 stopped containers, 0 images."* ]]
  [ "${#BCC_SKIPPED[@]}" -eq 0 ]
}

@test "C14: counts that could not be taken are said so, never given as 0" {
  touch "$D/psa-fails" "$D/images-fails"
  printf 'feed0001\n' >"$D/stopped"
  bcc_check_c14
  run info_text
  [[ $output == *"docker: 1 running containers, ? stopped containers, ? images."* ]]
  run skipped_text
  [[ $output == *"C14 (stopped containers)"$'\t''stopped containers and their inside: "docker ps -a" failed, so they were not counted'* ]]
  [[ $output == *"C14 (images)"$'\t''images and their inside: "docker images" failed, so they were not counted'* ]]
  # The running container is still looked inside.
  run findings_brief
  [[ $output == *"VULNERABLE|C14|node|container web (img:1) /usr/local/bin/node|22.23.3"* ]]
}

@test "C14: through another host's connection, stopped containers are counted on that context" {
  printf 'tcp://prod.example:2376\n' >"$D/ctx-prod"
  printf 'feed0001\n' >"$D/stopped"
  DOCKER_CONTEXT=prod bcc_check_c14
  grep -q '^tcp://prod.example:2376 | --context prod ps -a ' "$D/log"
  run skipped_text
  [[ $output == *"C14 (stopped containers)"$'\t'"inside of stopped containers (1 counted)"* ]]
  [[ $output == *"C14"$'\t'"inside of running containers: docker connects to tcp://prod.example:2376"* ]]
  nothing_ran_inside ' exec ' "$D/log"
}

@test "C14: without --inspect-containers, stopped containers and images are listed too" {
  BCC_INSPECT_CONTAINERS=0
  printf 'feed0001\n' >"$D/stopped"
  bcc_check_c14
  run skipped_text
  [[ $output == *"C14 (stopped containers)"$'\t'"inside of stopped containers (1 counted)"* ]]
  [[ $output == *"C14 (images)"$'\t'"inside of images (2 counted)"* ]]
  [[ $output == *"C14"$'\t'"inside of running containers (use --inspect-containers)"* ]]
}

@test "C14: podman's stopped containers are counted the same way" {
  fake_podman 'echo false'
  bcc_check_c14
  grep -q '^ps -a --format {{.ID}}$' "$D/podman-log"
  run skipped_text
  [[ $output == *"C14 (stopped containers)"$'\t'"inside of stopped containers (1 counted)"* ]]
  nothing_ran_inside '^exec feed' "$D/podman-log"
}

@test "C14: a stopped container is one that ps -a lists and ps does not, each counted once" {
  run bcc_c14_count_stopped $'0123abcd\timg:1\tweb\n4567cdef\timg:2\tdb' $'0123abcd\n4567cdef\nfeed0001\nfeed0001\n\n@\n*'
  [ "$output" = 3 ]
  run bcc_c14_count_stopped "" ""
  [ "$output" = 0 ]
}

@test "C14: the lines on stopped containers and images exist in Japanese too" {
  BCC_LANG=ja
  printf 'feed0001\nfeed0002\n' >"$D/stopped"
  bcc_check_c14
  run info_text
  [[ $output == *"docker: 実行中のコンテナ 1 個、止まっているコンテナ 2 個、イメージ 2 個。"* ]]
  run skipped_text
  [[ $output == *"C14 (stopped containers)"$'\t'"止まっているコンテナの中（2 個。数えただけで、--inspect-containers でも中では何も実行せず何も読まない）"* ]]
  [[ $output == *"C14 (images)"$'\t'"イメージの中（2 個。数えただけで、--inspect-containers でもイメージの中は見ない）"* ]]
}
