# Changelog

## [Unreleased]

### Added

- Configuration option `rowLimit` added ([#173]).
- Configuration and environment overrides enabled ([#173]).
- Ability to add MAPBOX_API_KEY from secret added ([#178]).
- Update SupersetConfigOptions to include explicit config for MapboxApiKey ([#179])
- Add support for LDAP authentication ([#180])
- [BREAKING] Specifying the product version has been changed to adhere to
  [ADR018](https://docs.stackable.tech/home/contributor/adr/ADR018-product_image_versioning.html)
  instead of just specifying the product version you will now have to add the
  Stackable image version as well, so `version: 1.4.1` becomes (for example)
  `version: 1.4.1-stackable2.1.0` ([#207])

### Changed

- Required product image version changed to 2 ([#182]).
- DruidConnection namespace properties are optional now ([#187]).

### Fixed

- A DruidConnection was not established if the Druid instance was started after
  the Superset instance, this was fixed ([#187]).
- The correct secret key is used when upgrading the Superset database. This
  issue was introduced in [#173] ([#190]).

[#173]: https://github.com/stackabletech/superset-operator/pull/173
[#178]: https://github.com/stackabletech/superset-operator/pull/178
[#179]: https://github.com/stackabletech/superset-operator/pull/179
[#180]: https://github.com/stackabletech/superset-operator/pull/180
[#182]: https://github.com/stackabletech/superset-operator/pull/182
[#187]: https://github.com/stackabletech/superset-operator/pull/187
[#190]: https://github.com/stackabletech/superset-operator/pull/190
[#207]: https://github.com/stackabletech/superset-operator/pull/207

## [0.4.0] - 2022-04-05

### Added

- Reconciliation errors are now reported as Kubernetes events ([#132]).
- Add support for Superset 1.4.1 ([#135]).
- Use cli argument `watch-namespace` / env var `WATCH_NAMESPACE` to specify
  a single namespace to watch ([#138]).

### Changed

- `operator-rs` `0.9.0` -> `0.13.0` ([#132],[#138]).

[#132]: https://github.com/stackabletech/superset-operator/pull/132
[#135]: https://github.com/stackabletech/superset-operator/pull/135
[#138]: https://github.com/stackabletech/superset-operator/pull/138

## [0.3.0] - 2022-02-14

### Added

- Druid DB connections can now be configured in a custom resource ([#71]).
- BREAKING: Prometheus metrics enabled ([#128]); The `statsdExporterVersion`
  must be set in the cluster specification.

### Changed

- Shut down gracefully ([#70]).
- All dependencies upgraded. The upgrade to operator-rs 0.8.0 does not
  force the credentials secret to be set anymore in the custom resource
  but it is still required ([#82]).
- `operator-rs` `0.8.0` → `0.9.0` ([#71])

[#70]: https://github.com/stackabletech/superset-operator/pull/70
[#71]: https://github.com/stackabletech/superset-operator/pull/71
[#82]: https://github.com/stackabletech/superset-operator/pull/82
[#128]: https://github.com/stackabletech/superset-operator/pull/128

## [0.2.0] - 2021-12-17


### Changed

- Migrated to StatefulSet rather than direct Pod management ([#45]).

[#45]: https://github.com/stackabletech/superset-operator/pull/45

## [0.1.0] - 2021-12-06

### Added
- Initial implementation of the operator added. An admin user can be created in the Superset
  database with the Init command which takes the credentials from a secret ([#7], [#12], [#33]).

[#7]: https://github.com/stackabletech/superset-operator/pull/7
[#12]: https://github.com/stackabletech/superset-operator/pull/12
[#33]: https://github.com/stackabletech/superset-operator/pull/33
