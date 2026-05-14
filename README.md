# VaporwareRMM Vantage

The federation control server for [VaporwareRMM Edge](https://github.com/doombadroid/VaporwareRMM-Edge) deployments.

## Status

Pre-implementation. The architecture is in active design — see the federation design issue in the Edge repo for current discussion.

## What this is

Vantage is the master/control plane for MSPs operating multiple customer sites via VaporwareRMM Edge appliances. Each customer site runs an Edge instance that manages endpoints locally. Vantage aggregates state, routes operator actions, and provides the MSP a single pane of glass across all sites.

Vantage is optional. VaporwareRMM Edge runs fully standalone for home users, self-hosters, and MSPs not doing federation.

## Roadmap

Implementation begins after the federation design lock in the Edge repo's federation issue.

## License

AGPL-3.0, same as VaporwareRMM Edge.
