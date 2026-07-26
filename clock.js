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
      const timer = setTimeout(resolve, ms);
      if (!cancellation) return;
      // Poll rather than use AbortSignal so the interface stays trivial.
      const poll = setInterval(() => {
        if (!cancellation.aborted) return;
        clearTimeout(timer);
        clearInterval(poll);
        resolve();
      }, 250);
      timer.unref?.();
      poll.unref?.();
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
