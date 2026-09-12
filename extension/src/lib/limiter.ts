/** Allows at most `max` sends per sliding window. */
export class Limiter {
  private sent: number[] = [];

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  /** Records a send at `now` when the budget allows; otherwise returns how long to wait. */
  reserve(now: number): number {
    const cutoff = now - this.windowMs;
    this.sent = this.sent.filter((t) => t > cutoff);
    if (this.sent.length < this.max) {
      this.sent.push(now);
      return 0;
    }
    return (this.sent[0] ?? now) - cutoff;
  }

  async wait(): Promise<void> {
    for (;;) {
      const delay = this.reserve(Date.now());
      if (delay === 0) {
        return;
      }
      await sleep(delay);
    }
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
