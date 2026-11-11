/**
 * Trusted time for the enforcer (AuthorityBench AB-40).
 *
 * Receipt expiry is only as good as the clock that checks it. If an attacker
 * can set the enforcer's local clock, an expired receipt becomes valid again.
 *
 * TimeAuthority signs {nonce, time}. TrustedClock asks it for the time with a
 * fresh random nonce and checks the signature, so neither a local clock change
 * nor a replayed old timestamp can move time backwards. This is the same idea
 * as Roughtime. TrustedClock also keeps a high-water mark and refuses any
 * reading that goes backwards.
 *
 * The authority's private key must live outside the agent's trust domain (a
 * separate service or HSM). In-process here for tests only.
 */
import { b64url, canonicalize, fromB64url, utf8 } from './canonical.ts';

export interface SignedTime {
  nonce: string;
  time: number;
  signature: string;
}

export class TimeAuthority {
  readonly publicKey: CryptoKey;
  #privateKey: CryptoKey;
  #now: () => number;

  private constructor(pair: CryptoKeyPair, now: () => number) {
    this.publicKey = pair.publicKey;
    this.#privateKey = pair.privateKey;
    this.#now = now;
  }

  static async create(now: () => number = Date.now): Promise<TimeAuthority> {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair;
    return new TimeAuthority(pair, now);
  }

  async stamp(nonce: string): Promise<SignedTime> {
    const body = { nonce, time: this.#now() };
    const sig = await crypto.subtle.sign('Ed25519', this.#privateKey, utf8(canonicalize(body)));
    return { ...body, signature: b64url(sig) };
  }
}

export class ClockError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/** Something the enforcer can ask for the current time. */
export interface EnforcerClock {
  now(): Promise<number>;
}

/**
 * Wraps a plain clock with a high-water mark: once it has read time t, any
 * later reading below t minus the allowed skew is refused.
 */
export class MonotonicClock implements EnforcerClock {
  #read: () => number;
  #high = -Infinity;
  #skewMs: number;
  constructor(read: () => number, skewMs = 5_000) {
    this.#read = read;
    this.#skewMs = skewMs;
  }
  async now(): Promise<number> {
    const t = this.#read();
    if (!Number.isFinite(t)) throw new ClockError('clock_invalid');
    if (t < this.#high - this.#skewMs) throw new ClockError('clock_rollback_detected');
    this.#high = Math.max(this.#high, t);
    return t;
  }
}

export class TrustedClock implements EnforcerClock {
  #authorityKey: CryptoKey;
  #fetch: (nonce: string) => Promise<SignedTime>;
  #high = -Infinity;

  /** `fetch` sends the nonce to the time authority over any channel; the signature is what is trusted. */
  constructor(authorityKey: CryptoKey, fetch: (nonce: string) => Promise<SignedTime>) {
    this.#authorityKey = authorityKey;
    this.#fetch = fetch;
  }

  async now(): Promise<number> {
    const nonce = crypto.randomUUID();
    const st = await this.#fetch(nonce);
    if (!st || st.nonce !== nonce) throw new ClockError('time_nonce_mismatch');
    if (typeof st.time !== 'number' || !Number.isFinite(st.time)) throw new ClockError('time_invalid');
    let ok = false;
    try {
      ok = await crypto.subtle.verify(
        'Ed25519',
        this.#authorityKey,
        fromB64url(st.signature),
        utf8(canonicalize({ nonce: st.nonce, time: st.time })),
      );
    } catch {
      ok = false;
    }
    if (!ok) throw new ClockError('time_signature_invalid');
    if (st.time < this.#high) throw new ClockError('clock_rollback_detected');
    this.#high = st.time;
    return st.time;
  }
}
