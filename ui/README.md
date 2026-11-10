# NS8 Fail2ban UI development

The module UI is based on Vue 2.7 and `@nethserver/ns8-ui-lib`.

Run a reproducible local build with:

    corepack enable
    yarn install --immutable
    yarn build

See the [NS8 module UI developer documentation](https://nethserver.github.io/ns8-core/ui/modules/#module-ui-development) for the development workflow.

## Dependency audit (2026-11-10)

The lockfile refresh stays within the existing dependency ranges; no Vue,
Carbon, ESLint or application-plugin major is replaced. The immutable lockfile
is the security fix, so no incompatible global resolution is necessary. Recheck
with `yarn npm audit --all --recursive` after future dependency updates.

Full recursive audit before/after the refresh (including deprecation notices):

| | Before | After |
| --- | ---: | ---: |
| High | 27 | 3 |
| Moderate | 16 | 6 |
| Low | 3 | 2 |
| Total findings | 46 | 11 |
| Security advisories (excluding deprecations) | 40 | 5 |

Compatible updates address ajv, ansi-regex, baseline-browser-mapping,
brace-expansion, browserslist, cross-spawn, js-yaml, lodash, minimatch (3.1.5),
semver, source-map-js, undici and word-wrap. Do not force minimatch 11 into the
ESLint 6 dependency tree: its CommonJS API and supported Node versions differ.
The audit returned no GHSA-g3hv-75wg-m249 finding for the resolved 3.1.5.

### Retained dependencies and diagnostics

- `lottie-web-vue` remains: ns8-ui-lib's `NsEmptyState` uses
  `NsLottieAnimation`, which imports it. The production build still reports
  `lottie-web`'s `eval` warning. Removing the package or suppressing the warning
  would not fix the library's dependency on it.
- `vue-axios` remains: ns8-ui-lib's task-service mixin calls `this.axios`;
  the application installs the plugin and configures its axios timeout.
- `vue-debounce` remains: ns8-ui-lib's `NsDataTable` and `NsComboSearchBox`
  use `v-debounce`. The application's global directive registration is required.
- Yarn reports the existing ESLint 6 / modern `@babel/eslint-parser` peer
  mismatch. A lint-stack migration is separate work; a package extension must
  not pretend that incompatible peer ranges are compatible.
- ns8-ui-lib declares Rollup plugins without providing their Rollup peer.
  This is upstream library-build metadata, not a missing browser runtime.
  Adding Rollup to the application would not repair that declaration.
- `/cluster-admin/css/core.css` is supplied by the NS8 host at runtime; its
  absence during a standalone Vite build is expected. No CJS/ESM build warning
  was observed.

The five remaining security advisories are two on `flatted@2.0.2`
(DoS/prototype pollution through ESLint's `flat-cache@2`), two on `tmp@0.0.33`
(path/symlink handling through ESLint's interactive `external-editor`), and
Vue 2's low-severity template-parser ReDoS. The first four are lint tooling,
not shipped application dependencies; their published fixes require leaving
those consumers' declared major ranges. The Vue issue requires a separately
scoped framework migration; never compile untrusted templates. Six additional
findings are deprecation notices for Carbon 10, ESLint 6, glob, inflight,
rimraf and vue-i18n 8. The audit intentionally remains nonzero; these findings
have not been hidden with audit exclusions.
