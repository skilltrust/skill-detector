// Package delta computes per-axis grade movement + finding diff between two
// scan results. Pure functions over pkg/model.ScanResult; no IO. Consumed by
// the `skill-detector delta` CLI sub-command and (via wrapper) by the
// skillmoss-go PR-comment bot.
package delta
