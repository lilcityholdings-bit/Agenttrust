export type Verdict = "ok" | "careful" | "stop";

export interface CheckResult {
  pay_to: string;
  verdict: Verdict;
  /** One plain sentence saying why. */
  advice: string;
  amount_usd: number | null;
  /** What the chain says about this wallet as a seller: payments, buyers, delivery reports, services. */
  evidence: Record<string, unknown>;
  /** Bots known to be paid at this wallet. */
  matches: Record<string, unknown>[];
  /** A page people can open: prefix with the Keptvow address. */
  wallet_page: string;
  /**
   * Keptvow's signature over this verdict (EIP-191 personal_sign), so it can be passed on and
   * still be proven genuine. The signer is published at /.well-known/keptvow-signer.json.
   */
  signed: { message: string; signature: string; signer: string; valid_until_ms: number };
}

export interface CheckOptions {
  /** The payment size in dollars; big payments need a stronger record. */
  amountUsd?: number;
  /** A Watch, Platform or credits key. Not needed for the free tier. */
  apiKey?: string;
  baseUrl?: string;
  /** false asks Keptvow every time instead of reusing a fresh signed answer. Default true. */
  cache?: boolean;
  fetch?: typeof fetch;
}

/** Asks Keptvow about one wallet before paying it. */
export function check(payTo: string, options?: CheckOptions): Promise<CheckResult>;

export interface GuardOptions {
  /** false also blocks wallets with no track record. Default true. */
  allowCareful?: boolean;
  /** false blocks payments when Keptvow can't be reached. Default true. */
  failOpen?: boolean;
  /** Called with each check result, e.g. for logging. */
  onCheck?: (result: CheckResult) => void;
  /** false turns off the background delivery reports. Default true. */
  reportOutcomes?: boolean;
  /** false asks Keptvow every time instead of reusing a fresh signed answer. Default true. */
  cache?: boolean;
  /** With a key, delivery reports make that seller's checks free. */
  apiKey?: string;
  baseUrl?: string;
}

/** Thrown instead of paying a wallet Keptvow says to stop at. */
export class KeptvowStop extends Error {
  check: CheckResult;
}

/**
 * Wraps fetch so every seller that answers 402 Payment Required is checked before any money
 * moves. Put it inside your x402 wrapper: wrapFetchWithPayment(withKeptvow(fetch), account).
 */
export function withKeptvow(fetchImpl?: typeof fetch, options?: GuardOptions): typeof fetch;

export default withKeptvow;
