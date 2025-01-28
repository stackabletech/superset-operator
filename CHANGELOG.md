# Changelog

## [Unreleased]

### Added

- Run a `containerdebug` process in the background of each Superset container to collect debugging information ([#578]).
- Aggregate emitted Kubernetes events on the CustomResources ([#585]).

[#578]: https://github.com/stackabletech/superset-operator/pull/578
[#585]: https://github.com/stackabletech/superset-operator/pull/585

## [24.11.1] - 2025-01-10

### Fixed

- Fix OIDC endpoint construction in case the `rootPath` does have a trailing slash ([#569]).
- BREAKING: Use distinct ServiceAccounts for the Stacklets, so that multiple Stacklets can be
  deployed in one namespace. Existing Stacklets will use the newly created ServiceAccounts after
  restart ([#568]).

[#568]: https://github.com/stackabletech/superset-operator/pull/568
[#569]: https://github.com/stackabletech/superset-operator/pull/569

## [24.11.0] - 2024-11-18

### Added

- Allowing arbitrary python code as EXPERIMENTAL_FILE_HEADER and EXPERIMENTAL_FILE_FOOTER in superset_config.py ([#530]).
- The operator can now run on Kubernetes clusters using a non-default cluster domain.
  Use the env var `KUBERNETES_CLUSTER_DOMAIN` or the operator Helm chart property `kubernetesClusterDomain` to set a non-default cluster domain ([#549]).

### Changed

- Reduce CRD size from `472KB` to `45KB` by accepting arbitrary YAML input instead of the underlying schema for the following fields ([#528]):
  - `podOverrides`
  - `affinity`

### Fixed

- Invalid `SupersetCluster`, `DruidConnection` or `AuthenticationClass` objects don't stop the operator from reconciling ([#551]).

[#528]: https://github.com/stackabletech/superset-operator/pull/528
[#530]: https://github.com/stackabletech/superset-operator/pull/530
[#549]: https://github.com/stackabletech/superset-operator/pull/549
[#551]: https://github.com/stackabletech/superset-operator/pull/551

## [24.7.0] - 2024-07-24

### Added

- Support for versions `3.1.3` and `4.0.2` ([#509]).

### Changed

- Bump `stackable-operator` to 0.70.0, `product-config` to 0.7.0, and other dependencies ([#511]).

### Fixed

- Don't print Superset admin credentials during startup ([#483]).
- Fix entrypoint to not throw `prepare_signal_handlers: command not found` in case DB initialization fails ([#485]).
- Processing of corrupted log events fixed; If errors occur, the error
  messages are added to the log event ([#502]).

### Removed

- Removed unsupported versions `2.1.1`, `3.0.1` and `3.0.3` ([#509]).

[#483]: https://github.com/stackabletech/superset-operator/pull/483
[#485]: https://github.com/stackabletech/superset-operator/pull/485
[#502]: https://github.com/stackabletech/superset-operator/pull/502
[#509]: https://github.com/stackabletech/superset-operator/pull/509
[#511]: https://github.com/stackabletech/superset-operator/pull/511

## [24.3.0] - 2024-03-20

### Added

- Improved CRD docs ([#431]).
- Helm: support labels in values.yaml ([#448]).
- Add support for OpenID Connect ([#423]).
- Support versions `2.1.3`, `3.0.3`, `3.1.0` ([#457]).

### Changed

- Raise memory requests and limits for Superset pods to 2Gi ([#468]).

### Fixed

- BREAKING: Fixed various issues in the CRD structure. `clusterConfig.credentialsSecret` is now mandatory ([#429]).

### Removed

- Removed support for version `2.1.0` ([#457]).

[#423]: https://github.com/stackabletech/superset-operator/pull/423
[#429]: https://github.com/stackabletech/superset-operator/pull/429
[#431]: https://github.com/stackabletech/superset-operator/pull/431
[#448]: https://github.com/stackabletech/superset-operator/pull/448
[#457]: https://github.com/stackabletech/superset-operator/pull/457
[#468]: https://github.com/stackabletech/superset-operator/pull/468

## [23.11.0] - 2023-11-24

### Added

- Default stackableVersion to operator version ([#390]).
- Support PodDisruptionBudgets ([#407]).
- Added support for versions 2.1.1, 3.0.1 ([#415]).
- Support graceful shutdown ([#422]).

### Changed

- `vector` `0.26.0` -> `0.33.0` ([#391], [#415]).
- `operator-rs` `0.44.0` -> `0.55.0` ([#390], [#407], [#415]).
- BREAKING: Removed SupersetDB object, since it created some problems when reinstalling or upgrading a Superset cluster. Instead, the initialization of the database was moved to the startup phase of each Superset pod. To make sure the initialization does not run in parallel, the `PodManagementPolicy` was set to `OrderedReady` and liveness/readiness probes were added. The `.spec.clusterConfig.loadExamplesOnInit` option was removed from the CRD, because loading the examples at every startup caused problems in certain scenarios, e.g. after an upgrade from Superset 1.5.3 to 2.1.0 ([#396]).

### Fixed

- BREAKING: Rename Service port name from `superset` to `http` for consistency reasons. This change should normally not be breaking, as we only change the name, not the port. However, there might be some e.g. Ingresses that rely on the port name and need to be updated ([#394]).
- Fixed config override support ([#415]).

### Removed

- Removed support for versions 1.3.2, 1.4.1, 1.4.2, 1.5.1, 1.5.3, 2.0.1 ([#415]).

[#390]: https://github.com/stackabletech/superset-operator/pull/390
[#391]: https://github.com/stackabletech/superset-operator/pull/391
[#394]: https://github.com/stackabletech/superset-operator/pull/394
[#396]: https://github.com/stackabletech/superset-operator/pull/396
[#407]: https://github.com/stackabletech/superset-operator/pull/407
[#415]: https://github.com/stackabletech/superset-operator/pull/415
[#422]: https://github.com/stackabletech/superset-operator/pull/422

## [23.7.0] - 2023-07-14

### Added

- Added support for Superset versions `1.4.2`, `1.5.3`, `2.0.1` and `2.1.0` ([#362]).
- Generate OLM bundle for Release 23.4.0 ([#364]).
- Missing CRD defaults for `status.conditions` field ([#367]).
- Set explicit resources on all containers ([#371]).
- Support podOverrides ([#377]).

### Changed

- `operator-rs` `0.40.2` -> `0.44.0` ([#360], [#371], [#383]).
- Use 0.0.0-dev product images for testing ([#361]).
- Use testing-tools 0.2.0 ([#361]).
- Added kuttl test suites ([#373]).
- [BREAKING] Moved all top level config options to `clusterConfig`. Authentication is now provided via an array of AuthenticationClasses and additional properties ([#379]).

### Fixed

- Operator now errors out when `credentialsSecret` is missing ([#375]).
- Increase the size limit of the log volume ([#383]).

[#360]: https://github.com/stackabletech/superset-operator/pull/360
[#361]: https://github.com/stackabletech/superset-operator/pull/361
[#362]: https://github.com/stackabletech/superset-operator/pull/362
[#364]: https://github.com/stackabletech/superset-operator/pull/364
[#367]: https://github.com/stackabletech/superset-operator/pull/367
[#371]: https://github.com/stackabletech/superset-operator/pull/371
[#373]: https://github.com/stackabletech/superset-operator/pull/373
[#375]: https://github.com/stackabletech/superset-operator/pull/375
[#377]: https://github.com/stackabletech/superset-operator/pull/377
[#379]: https://github.com/stackabletech/superset-operator/pull/379
[#383]: https://github.com/stackabletech/superset-operator/pull/383

## [23.4.0] - 2023-04-17

### Added

- Log aggregation added ([#326]).
- Deploy default and support custom affinities ([#337]).
- Extend cluster resources for status and cluster operation (paused, stopped) ([#348])
- Cluster status conditions ([#349])

### Changed

- [BREAKING]: Support specifying Service type by moving `serviceType` (which was an experimental feature) to `clusterConfig.listenerClass`.
  This enables us to later switch non-breaking to using `ListenerClasses` for the exposure of Services.
  This change is breaking, because - for security reasons - we default to the `cluster-internal` `ListenerClass`.
  If you need your cluster to be accessible from outside of Kubernetes you need to set `clusterConfig.listenerClass`
  to `external-unstable` or `external-stable` ([#350]).
- `operator-rs` `0.31.0` -> `0.35.0` -> `0.40.2`  ([#322], [#326], [#352]).
- Bumped stackable image versions to "23.4.0-rc2" ([#322], [#326]).
- Fragmented `SupersetConfig` ([#323]).
- Restructured documentation ([#344]).
- Create `ServiceAccount` for Superset clusters. Use `build_rbac_resources()` from operator-rs ([#352])

[#322]: https://github.com/stackabletech/superset-operator/pull/322
[#323]: https://github.com/stackabletech/superset-operator/pull/323
[#326]: https://github.com/stackabletech/superset-operator/pull/326
[#337]: https://github.com/stackabletech/superset-operator/pull/337
[#344]: https://github.com/stackabletech/superset-operator/pull/344
[#348]: https://github.com/stackabletech/superset-operator/pull/348
[#349]: https://github.com/stackabletech/superset-operator/pull/349
[#350]: https://github.com/stackabletech/superset-operator/pull/350
[#352]: https://github.com/stackabletech/superset-operator/pull/352

## [23.1.0] - 2023-01-23

### Changed

- `operator-rs` `0.27.1` -> `0.31.0` ([#306], [#297], [#311])
- Fixed the RoleGroup `selector`. It was not used before. ([#306])
- Updated stackable image versions ([#295])
- [BREAKING] Use Product image selection instead of version ([#304])
  - `spec.version` has been replaced by `spec.image`
  - `spec.statsdExporterVersion` has been removed, the statsd-exporter is now part of the images itself
- Refactored LDAP authentication handling to use functionality from the `LdapAuthenticationProvider` ([#311])

[#306]: https://github.com/stackabletech/superset-operator/pull/306
[#295]: https://github.com/stackabletech/superset-operator/pull/295
[#297]: https://github.com/stackabletech/superset-operator/pull/297
[#304]: https://github.com/stackabletech/superset-operator/pull/304
[#311]: https://github.com/stackabletech/superset-operator/pull/311

## [0.7.0] - 2022-11-07

### Added

- CPU and memory limits are now configurable ([#273]).

### Changed

- Don't run init container as root and avoid chmod and chowning ([#300]).

[#273]: https://github.com/stackabletech/superset-operator/pull/273
[#300]: https://github.com/stackabletech/superset-operator/pull/300

## [0.6.0] - 2022-09-07

### Added

- Add temporary attribute to support using ClusterIP instead of NodePort service type ([#266]).

### Changed

- Include chart name when installing with a custom release name ([#227], [#228]).
- Orphaned resources are deleted ([#255]).
- `operator-rs` `0.22.0` -> `0.25.0` ([#255]).
- Make webserver timeout configurable. Increase default to 5m ([#247]).

[#227]: https://github.com/stackabletech/superset-operator/pull/227
[#228]: https://github.com/stackabletech/superset-operator/pull/228
[#247]: https://github.com/stackabletech/superset-operator/pull/247
[#255]: https://github.com/stackabletech/superset-operator/pull/255
[#266]: https://github.com/stackabletech/superset-operator/pull/266

## [0.5.0] - 2022-06-30

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
- Add support for Superset 1.5.1 ([#222]).

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
[#222]: https://github.com/stackabletech/superset-operator/pull/222

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
