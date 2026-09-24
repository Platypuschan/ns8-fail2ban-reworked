#!/bin/bash
# Disposable Rocky Linux / NS8 VM. Images stay in a registry on this CI runner.
set -Eeuo pipefail
ci_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/f2b-ns8-ci.XXXXXX")"
ssh_args=(-p 2222 -i "$ci_dir/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=20 -o LogLevel=ERROR)
ssh_ci() { ssh "${ssh_args[@]}" root@127.0.0.1 "$@"; }
cleanup() {
    mkdir -p tests/outputs
    cp "$ci_dir/console.log" tests/outputs/console.log 2>/dev/null || true
    ssh_ci 'journalctl --no-pager -b' >tests/outputs/journal.log 2>/dev/null || true
    ssh_ci 'systemctl --failed --no-pager; podman ps -a; nft list ruleset' >tests/outputs/state.log 2>/dev/null || true
    if [[ -f "$ci_dir/qemu.pid" ]]; then kill "$(cat "$ci_dir/qemu.pid")" 2>/dev/null || true; fi
    podman rm -f ns8-ci-registry >/dev/null 2>&1 || true
    rm -rf "$ci_dir"
}
trap cleanup EXIT
test -e /dev/kvm
sudo setfacl -m "u:$USER:rw" /dev/kvm
podman run --detach --name ns8-ci-registry --network=host docker.io/library/registry:2.8.3
for attempt in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:5000/v2/ >/dev/null; then break; fi
    sleep 1
done
engine="$(cat .build/images/engine-reference)"
skopeo copy --dest-tls-verify=false "oci-archive:$PWD/.build/images/engine.oci" "docker://127.0.0.1:5000/${engine#10.0.2.2:5000/}"
skopeo copy --dest-tls-verify=false "oci-archive:$PWD/.build/images/module.oci" docker://127.0.0.1:5000/ns8-ci/fail2ban-reworked:ci

base='https://dl.rockylinux.org/pub/rocky/9/images/x86_64'
filename='Rocky-9-GenericCloud-Base.latest.x86_64.qcow2'
curl -fsSL --retry 3 "$base/CHECKSUM" -o "$ci_dir/CHECKSUM"
checksum="$(awk -v name="($filename)" '$2 == name {print $4}' "$ci_dir/CHECKSUM")"
[[ "$checksum" =~ ^[a-fA-F0-9]{64}$ ]]
curl -fsSL --retry 3 "$base/$filename" -o "$ci_dir/base.qcow2"
printf '%s  %s\n' "$checksum" "$ci_dir/base.qcow2" | sha256sum -c -
qemu-img resize "$ci_dir/base.qcow2" 24G
ssh-keygen -q -t ed25519 -N '' -f "$ci_dir/key"
public_key="$(cat "$ci_dir/key.pub")"
cat >"$ci_dir/user-data" <<EOF
#cloud-config
hostname: ns8-ci
fqdn: ns8-ci.test.local
manage_etc_hosts: false
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - "$public_key"
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
write_files:
  - path: /etc/ssh/sshd_config.d/00-ci.conf
    permissions: '0600'
    content: |
      PermitRootLogin prohibit-password
      PubkeyAuthentication yes
  - path: /etc/containers/registries.conf.d/ci.conf
    permissions: '0644'
    content: |
      [[registry]]
      location = "10.0.2.2:5000"
      insecure = true
runcmd:
  - [bash, -c, 'echo "10.0.2.15 ns8-ci.test.local ns8-ci" >> /etc/hosts']
  - [systemctl, restart, sshd]
EOF
printf 'instance-id: ns8-fail2ban-ci\nlocal-hostname: ns8-ci\n' >"$ci_dir/meta-data"
cloud-localds "$ci_dir/seed.iso" "$ci_dir/user-data" "$ci_dir/meta-data"
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 4 -m 8192 \
    -display none -monitor none -serial "file:$ci_dir/console.log" \
    -device virtio-rng-pci \
    -drive "if=virtio,file=$ci_dir/base.qcow2,format=qcow2,cache=unsafe" \
    -drive "if=virtio,file=$ci_dir/seed.iso,format=raw,readonly=on" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=n0 -daemonize -pidfile "$ci_dir/qemu.pid"
ready=0
for attempt in $(seq 1 120); do
    if ssh_ci true 2>/dev/null; then ready=1; break; fi
    sleep 2
done
test "$ready" = 1
ssh_ci 'cloud-init status --wait --long'
ssh_ci 'curl -fsSL --retry 3 https://raw.githubusercontent.com/NethServer/ns8-core/ns8-stable/core/install.sh -o /root/install-ns8.sh && bash /root/install-ns8.sh'
ssh_ci 'create-cluster 10.0.2.15:55820 10.5.4.0/24 Nethesis,1234'
for name in ns8-smoke.py ns8-smoke.sh ns8-notify-sink.py; do
    ssh_ci "cat > /tmp/$name" <"tests/$name"
done
ssh_ci bash /tmp/ns8-smoke.sh 10.0.2.2:5000/ns8-ci/fail2ban-reworked:ci
