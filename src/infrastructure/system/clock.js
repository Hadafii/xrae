// LAYER: infrastructure
// JOB:   Provide the current time and the ability to wait.
// IMPLEMENTS: Clock port.
//
// Time is injected rather than read from the global Date/setTimeout so that
// tests can advance hours instantly. Without this, testing score decay would
// mean actually waiting 24 hours.

/** @implements {import('../../application/ports.js').Clock} */
export class SystemClock {
  nowMs() {
    return Date.now();
  }

  /**
   * @param {number} ms
   * @param {{aborted: boolean}} [cancellation] lets shutdown interrupt a long sleep
   */
  sleep(ms, cancellation) {
    if (ms <= 0) return Promise.resolve();
    return new Promise((resolve) => {
      let timer;
      let poll;
      // Clean up BOTH handles on resolve. This matters twice over:
      //   - The timer must stay ref'd (not unref'd) so that in `run` mode the
      //     inter-cycle sleep keeps the process alive between scans. Unref'ing
      //     it made Node's event loop empty and the process exit 0 the instant
      //     a cycle finished, so systemd saw a clean exit and the agent
      //     silently stopped after one cycle.
      //   - But a ref'd poll interval that is never cleared would keep the
      //     process alive forever after the sleep resolves. So clear both here.
      const done = () => {
        clearTimeout(timer);
        clearInterval(poll);
        resolve();
      };

      timer = setTimeout(done, ms);
      if (!cancellation) return;
      // Poll rather than use AbortSignal so the interface stays trivial.
      poll = setInterval(() => {
        if (cancellation.aborted) done();
      }, 250);
    });
  }
}

/**
 * A clock you control. `advance()` moves time forward without waiting.
 * @implements {import('../../application/ports.js').Clock}
 */
export class FakeClock {
  constructor(startMs = 1_700_000_000_000) {
    this.current = startMs;
  }
  nowMs() {
    return this.current;
  }
  async sleep(ms) {
    this.current += ms;
  }
  advanceHours(hours) {
    this.current += hours * 3_600_000;
  }
}
