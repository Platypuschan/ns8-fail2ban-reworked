#!/bin/bash
set -Eeuo pipefail
repobase="${REPOBASE:-ghcr.io/platypuschan}"
repobase="${repobase,,}"
revision="$(git rev-parse --short=12 HEAD)"
engine="${repobase}/fail2ban-engine:1.1.1-${revision}"
module="${repobase}/fail2ban-reworked"
context="$(mktemp -d)"
builder=""
cleanup() {
    rm -rf "${context}"
    if [[ -n "${builder}" ]]; then buildah rm "${builder}" >/dev/null; fi
}
trap cleanup EXIT
git clone --quiet --depth=1 --branch=1.1.1 https://github.com/fail2ban/fail2ban.git "${context}/fail2ban"
test "$(git -C "${context}/fail2ban" rev-parse HEAD)" = f60978618a101427b06924fc932b44350fec2b63
rm -rf "${context}/fail2ban/.git"
cp runtime/{Containerfile,entrypoint.py,control.py,ns8_action.py} "${context}/"
cp -a imageroot/pypkg/f2bns8 "${context}/"
buildah bud -t "${engine}" "${context}"
if [[ ! -d ui/dist ]]; then
    (cd ui && env -u YARN_NO_PROXY NODE_OPTIONS=--openssl-legacy-provider corepack yarn install --immutable && env -u YARN_NO_PROXY NODE_OPTIONS=--openssl-legacy-provider corepack yarn build)
fi
builder="$(buildah from scratch)"
buildah add "${builder}" imageroot /imageroot
buildah add "${builder}" ui/dist /ui
buildah config --entrypoint=/ \
    --label="org.opencontainers.image.source=https://github.com/Platypuschan/ns8-fail2ban-reworked" \
    --label="org.nethserver.authorizations=traefik@node:routeadm" \
    --label="org.nethserver.tcp-ports-demand=1" \
    --label="org.nethserver.rootfull=1" \
    --label="org.nethserver.max-per-node=1" \
    --label="org.nethserver.min-core=3.2.2" \
    --label="org.nethserver.images=${engine}" "${builder}"
buildah commit "${builder}" "${module}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'engine=%s\nmodule=%s\n' "${engine}" "${module}" >>"${GITHUB_OUTPUT}"
fi
printf 'Built %s and %s\n' "${module}" "${engine}"
