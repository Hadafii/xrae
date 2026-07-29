// LAYER: shared
// JOB:   One place that knows what version this agent is.
//
// It lives here rather than in src/cli/, because the composition root reports
// the version to the panel and must not import from the CLI: the CLI imports
// the composition root, and the reverse would be a cycle.

export const VERSION = '1.0.0';
