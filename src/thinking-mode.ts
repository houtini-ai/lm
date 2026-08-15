export type ThinkingOverride = boolean | undefined;

/**
 * Resolve HOUTINI_LM_THINKING into the value sent to the backend.
 *
 * `on` and `off` are explicit operator overrides. `auto` preserves the
 * existing behaviour: suppress thinking only when model detection says the
 * backend supports the toggle. Unknown values fall back to `auto`.
 */
export function resolveThinkingOverride(
  rawMode: string | undefined,
  supportsThinkingToggle: boolean,
): ThinkingOverride {
  const mode = (rawMode || 'auto').toLowerCase();

  if (mode === 'on') return true;
  if (mode === 'off') return false;
  return supportsThinkingToggle ? false : undefined;
}
