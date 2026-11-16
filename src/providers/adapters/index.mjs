import { siliconflowAdapter } from './siliconflow.mjs';
import { deepseekAdapter } from './deepseek.mjs';
import { emrankAdapter } from './emrank.mjs';

const ADAPTERS = new Map([
  ['siliconflow', siliconflowAdapter],
  ['emrank', emrankAdapter],
  ['deepseek', deepseekAdapter]
]);

export function getProviderAdapter(provider) {
  const key = String(provider || '').trim().toLowerCase();
  const adapter = ADAPTERS.get(key);
  if (!adapter) {
    const err = new Error(`[ERR_UNSUPPORTED_PROVIDER] No adapter registered for provider=${String(provider)}`);
    err.code = 'ERR_UNSUPPORTED_PROVIDER';
    throw err;
  }
  return adapter;
}

export function getAdapterForPurpose({ provider, purpose }) {
  const adapter = getProviderAdapter(provider);
  if (!Array.isArray(adapter.supportedPurposes) || !adapter.supportedPurposes.includes(purpose)) {
    const err = new Error(
      `[ERR_UNSUPPORTED_PURPOSE] Provider ${adapter.provider} does not support purpose=${String(purpose)}`
    );
    err.code = 'ERR_UNSUPPORTED_PURPOSE';
    throw err;
  }
  return adapter;
}

export { siliconflowAdapter, emrankAdapter, deepseekAdapter };
