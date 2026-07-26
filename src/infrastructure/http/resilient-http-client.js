// LAYER: infrastructure
// JOB:   Make HTTP requests that survive a flaky or overloaded panel.
//
// Three separate concerns live here, each in its own small class:
//   RetryPolicy     - decides IF and WHEN to try again
//   CircuitBreaker  - decides whether to try at all right now
//   ResilientHttpClient - actually performs the request
//
// They are separate because they change for different reasons. Tuning retry
// timings should never risk breaking the breaker, and vice versa.

/** Thrown for any HTTP-level failure. Carries enough context to act on. */
export class HttpError extends Error {
  constructor(message, { status = 0, body = '', retryable = false, cause } = {}) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.body = body;
    this.retryable = retryable;
    if (cause) this.cause = cause;
  }
}

/**
 * Which failures are worth trying again.
 *
 * Note what is NOT here: 401, 403 and 404. Those mean the configuration is
 * wrong. Retrying them just delays the moment the operator learns the truth,
 * and burns rate limit doing it.
 */
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

const RETRYABLE_NETWORK_CODES = new Set([
  'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'EPIPE', 'ENOTFOUND',
  'EHOSTUNREACH', 'ENETUNREACH', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_SOCKET',
]);

export class RetryPolicy {
  /**
   * @param {object} options
   * @param {number} options.maxAttempts
   * @param {number} options.baseDelayMs
   * @param {number} options.maxDelayMs
   * @param {number} options.maxRetryAfterMs  ignore absurd Retry-After values
   * @param {() => number} [options.random]   injectable for deterministic tests
   */
  constructor({ maxAttempts, baseDelayMs, maxDelayMs, maxRetryAfterMs, random = Math.random }) {
    this.maxAttempts = Math.max(1, maxAttempts);
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs;
    this.maxRetryAfterMs = maxRetryAfterMs;
    this.random = random;
  }

  isRetryableStatus(status) {
    return RETRYABLE_STATUS.has(status);
  }

  isRetryableNetworkError(error) {
    const code = error?.cause?.code ?? error?.code;
    const isTimeout = error?.name === 'TimeoutError' || error?.name === 'AbortError';
    return isTimeout || RETRYABLE_NETWORK_CODES.has(code);
  }

  /**
   * Exponential backoff with FULL JITTER.
   *
   * The jitter matters more than it looks: without it, twenty nodes that all
   * failed at the same moment retry at the same moment, and keep hammering the
   * panel in lockstep until something gives.
   *
   * @param {number} attemptIndex zero-based
   */
  delayFor(attemptIndex) {
    const ceiling = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attemptIndex);
    return Math.floor(this.random() * ceiling);
  }

  /** Honour a server-provided Retry-After header, in seconds or as a date. */
  delayFromRetryAfter(headerValue) {
    if (!headerValue) return null;

    const seconds = Number(headerValue);
    if (Number.isFinite(seconds)) return Math.min(seconds * 1000, this.maxRetryAfterMs);

    const timestamp = Date.parse(headerValue);
    if (Number.isFinite(timestamp)) {
      return Math.min(Math.max(0, timestamp - Date.now()), this.maxRetryAfterMs);
    }
    return null;
  }
}

/**
 * Stops calling a service that is clearly down.
 *
 * States: closed (normal) -> open (fail fast) -> half-open (one probe) -> closed.
 */
export class CircuitBreaker {
  /**
   * @param {object} options
   * @param {string} options.name
   * @param {number} options.failureThreshold
   * @param {number} options.cooldownMs
   * @param {import('../../application/ports.js').Clock} options.clock
   * @param {import('../../application/ports.js').Logger} options.logger
   */
  constructor({ name, failureThreshold, cooldownMs, clock, logger }) {
    this.name = name;
    this.failureThreshold = failureThreshold;
    this.cooldownMs = cooldownMs;
    this.clock = clock;
    this.logger = logger;
    this.consecutiveFailures = 0;
    this.openedAtMs = 0;
  }

  get isOpen() {
    if (!this.openedAtMs) return false;

    if (this.clock.nowMs() - this.openedAtMs >= this.cooldownMs) {
      this.openedAtMs = 0;
      this.consecutiveFailures = this.failureThreshold - 1; // half-open: one probe
      this.logger.info(`circuit "${this.name}" is half-open, sending one probe`);
      return false;
    }
    return true;
  }

  get msUntilRetry() {
    return this.openedAtMs ? Math.max(0, this.cooldownMs - (this.clock.nowMs() - this.openedAtMs)) : 0;
  }

  recordSuccess() {
    this.consecutiveFailures = 0;
    this.openedAtMs = 0;
  }

  recordFailure() {
    this.consecutiveFailures += 1;
    if (this.consecutiveFailures >= this.failureThreshold && !this.openedAtMs) {
      this.openedAtMs = this.clock.nowMs();
      this.logger.warn(
        `circuit "${this.name}" opened after ${this.consecutiveFailures} consecutive failures; ` +
          `pausing for ${Math.round(this.cooldownMs / 1000)}s`,
      );
    }
  }
}

export class ResilientHttpClient {
  /**
   * @param {object} deps
   * @param {RetryPolicy} deps.retryPolicy
   * @param {CircuitBreaker} deps.circuitBreaker
   * @param {import('../../application/ports.js').Logger} deps.logger
   * @param {import('../../application/ports.js').Clock} deps.clock
   * @param {number} deps.timeoutMs
   * @param {typeof fetch} [deps.fetchImpl]  injectable for tests
   */
  constructor({ retryPolicy, circuitBreaker, logger, clock, timeoutMs, fetchImpl = fetch }) {
    this.retryPolicy = retryPolicy;
    this.circuitBreaker = circuitBreaker;
    this.logger = logger;
    this.clock = clock;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  /**
   * @param {string} url
   * @param {object} [options]
   * @param {string} [options.method]
   * @param {Record<string,string>} [options.headers]
   * @param {string} [options.body]
   * @param {boolean} [options.parseJson]
   * @param {string} [options.label]  appears in logs; never include secrets
   * @returns {Promise<{status: number, data: any, raw: string}>}
   */
  async send(url, options = {}) {
    const { method = 'GET', headers = {}, body, parseJson = true, label = method } = options;

    if (this.circuitBreaker.isOpen) {
      throw new HttpError(
        `${label}: circuit breaker is open, retry in ${Math.ceil(this.circuitBreaker.msUntilRetry / 1000)}s`,
      );
    }

    let lastError;

    for (let attempt = 0; attempt < this.retryPolicy.maxAttempts; attempt += 1) {
      const isLastAttempt = attempt === this.retryPolicy.maxAttempts - 1;

      try {
        const response = await this.fetchImpl(url, {
          method,
          headers,
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        const raw = await response.text();

        if (response.ok) {
          this.circuitBreaker.recordSuccess();
          return { status: response.status, data: parseJson && raw ? JSON.parse(raw) : null, raw };
        }

        const retryable = this.retryPolicy.isRetryableStatus(response.status);
        lastError = new HttpError(`${label}: HTTP ${response.status}`, {
          status: response.status,
          body: raw.slice(0, 400),
          retryable,
        });

        if (!retryable) {
          // A 4xx means the service is UP and answered - it is a per-request
          // verdict (forbidden, not found), not an outage. Best-effort calls
          // like per-server CPU metrics routinely 403/404 on servers the client
          // key does not own; letting those open the shared panel breaker would
          // take down the critical server-list and suspend calls with them.
          // Only a genuine server-side failure (5xx) trips the breaker here.
          if (response.status >= 500) this.circuitBreaker.recordFailure();
          throw lastError;
        }
        if (isLastAttempt) break;

        const hinted = this.retryPolicy.delayFromRetryAfter(response.headers.get('retry-after'));
        const delay = hinted ?? this.retryPolicy.delayFor(attempt);
        this.logger.warn(`${label} got ${response.status}; retrying in ${delay}ms`);
        await this.clock.sleep(delay);
      } catch (error) {
        if (error instanceof HttpError && !error.retryable) throw error;

        if (!this.retryPolicy.isRetryableNetworkError(error) && !(error instanceof HttpError)) {
          this.circuitBreaker.recordFailure();
          throw new HttpError(`${label}: ${error.message}`, { cause: error });
        }

        lastError = error instanceof HttpError ? error : new HttpError(`${label}: ${error.message}`, { cause: error });
        if (isLastAttempt) break;

        const delay = this.retryPolicy.delayFor(attempt);
        this.logger.warn(`${label} failed (${lastError.message}); retrying in ${delay}ms`);
        await this.clock.sleep(delay);
      }
    }

    this.circuitBreaker.recordFailure();
    throw lastError ?? new HttpError(`${label}: all ${this.retryPolicy.maxAttempts} attempts failed`);
  }
}
