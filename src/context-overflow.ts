/**
 * context-overflow.ts — recover the real context limit from a backend's 400.
 *
 * Strict OpenAI-compatible backends (notably vLLM) reject a request when
 * prompt + max_tokens exceeds the model's context window with an HTTP 400,
 * rather than silently clamping. houtini-lm sizes its output budget from the
 * context it detects via /v1/models — but that number can be wrong when a
 * proxy sits in front (e.g. a LiteLLM router advertising a generic 100k window
 * while the model actually loaded is 64k). The result is a spurious 400 on a
 * request that only overshot because the advertised context was too large.
 *
 * The server's own error message states the real limit. Parsing it lets the
 * caller retry once with a corrected budget — robust even when /v1/models
 * mis-reports the context behind a proxy, and self-correcting across backends.
 */

/**
 * Extract the real maximum context length (tokens) a backend reports in a
 * context-overflow error message. Returns the limit, or null if the text is not
 * a recognisable context-overflow error.
 *
 * Recognised shapes (case-insensitive):
 *   vLLM:      "max_completion_tokens=99002 cannot be greater than max_model_len=max_total_tokens=65536"
 *   OpenAI:    "This model's maximum context length is 65536 tokens"
 *   generic:   "... context length/size/window ... 65536 ..."
 *   llama.cpp: "the request exceeds the available context size ... n_ctx = 65536"
 */
export function parseContextOverflow(text: string): number | null {
  if (!text) return null;
  const patterns: RegExp[] = [
    /max_model_len\D*([\d,]{2,})/i,               // vLLM — grabs the final number after max_model_len
    /maximum context length is\s*([\d,]{2,})/i,   // OpenAI
    /context (?:length|size|window)\D*([\d,]{2,})/i,
    /n_ctx\s*=\s*([\d,]{2,})/i,                    // llama.cpp
  ];
  for (const p of patterns) {
    const m = text.match(p);
    if (m) {
      // Numbers may carry thousands separators ("65,536"); strip before parsing.
      const cleaned = m[1].replace(/,/g, '');
      if (/^\d{2,}$/.test(cleaned)) {
        const n = Number(cleaned);
        if (Number.isFinite(n) && n > 0) return n;
      }
    }
  }
  return null;
}

/**
 * Given the real context limit and a prompt-size estimate, compute a safe
 * output budget that leaves room for the prompt. Mirrors the caller's original
 * cap heuristic (≈3 chars/token + per-message overhead + a margin) so a retry
 * lands comfortably inside the window. Never returns below `floor`.
 */
export function correctedMaxTokens(
  realContextLen: number,
  promptChars: number,
  messageCount: number,
  floor = 256,
): number {
  const promptEstimate = Math.ceil(promptChars / 3) + 64 * messageCount + 512;
  return Math.max(floor, realContextLen - promptEstimate);
}
