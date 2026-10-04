//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Browser replacement for the Node "crypto" module. ns8-ui-lib generates
// task event IDs with uuid v3, which calls crypto.randomBytes(). Vue CLI 4
// (webpack 4) polyfilled "crypto" automatically; Vite does not, so without
// this shim every getUuid() call throws and no module task is ever started.
//
export function randomBytes(size) {
  return window.crypto.getRandomValues(new Uint8Array(size));
}

export default { randomBytes };
