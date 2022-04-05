# Changelog

## [Unreleased]

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
