import { extractStandardUsage } from './siliconflow.mjs';

function createAdapterError(code, message, extra = {}) {
  const err = new Error(`[${code}] ${message}`);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

function assertValidMaxTokens(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw createAdapterError(
      'ERR_INVALID_MAX_TOKENS',
      `DeepSeek maxTokens must be a positive safe integer, got ${String(value)}`
    );
  }
  return value;
}

function parseStrictJsonObject(rawContent, purpose) {
  let parsed;
  try {
    parsed = JSON.parse(String(rawContent || '').trim());
  } catch (err) {
    throw createAdapterError(
      'ERR_PROVIDER_INVALID_JSON_CONTENT',
      `DeepSeek ${purpose} response content is not valid JSON: ${err.message}`
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw createAdapterError(
      'ERR_PROVIDER_INVALID_JSON_CONTENT',
      `DeepSeek ${purpose} response JSON must be a plain object`
    );
  }
  return parsed;
}

export const deepseekAdapter = Object.freeze({
  provider: 'deepseek',
  supportedPurposes: Object.freeze(['distill', 'judge']),
  // DeepSeek OpenAI-compatible API reports completion_tokens already including reasoning_tokens.
  completionIncludesReasoning: true,

  getEndpointPath(purpose) {
    if (purpose === 'distill' || purpose === 'judge') {
      return '/v1/chat/completions';
    }
    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `DeepSeek adapter does not support purpose=${purpose}`);
  },

  getAcceptedEndpointPaths(purpose) {
    if (purpose === 'distill' || purpose === 'judge') {
      return ['/v1/chat/completions', '/chat/completions'];
    }
    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `DeepSeek adapter does not support purpose=${purpose}`);
  },

  buildRequest({
    purpose,
    model,
    messages,
    maxTokens = null,
    temperature = undefined,
    thinkingMode = null,
    responseFormat = null
  }) {
    if (purpose !== 'distill' && purpose !== 'judge') {
      throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `DeepSeek adapter does not support purpose=${purpose}`);
    }
    if (typeof model !== 'string' || model.trim().length === 0) {
      throw createAdapterError('ERR_INVALID_MODEL', 'model must be a non-empty string');
    }
    if (!Array.isArray(messages) || messages.length === 0) {
      throw createAdapterError(
        purpose === 'judge' ? 'ERR_INVALID_JUDGE_INPUT' : 'ERR_INVALID_DISTILL_INPUT',
        'messages must be a non-empty array'
      );
    }

    const cleanModel = model.trim();
    const isReasonerModel = cleanModel === 'deepseek-reasoner';
    if (isReasonerModel && thinkingMode === false) {
      throw createAdapterError(
        'ERR_INVALID_THINKING_MODE',
        'deepseek-reasoner cannot disable thinking mode'
      );
    }
    const thinkingEnabled = isReasonerModel || thinkingMode === true;

    const defaultMaxTokens = purpose === 'judge' ? 1024 : thinkingEnabled ? 4096 : 2048;
    const hardMaxTokens = assertValidMaxTokens(
      maxTokens === null || maxTokens === undefined ? defaultMaxTokens : maxTokens
    );

    const body = {
      model: cleanModel,
      messages,
      max_tokens: hardMaxTokens,
      stream: false
    };

    if (thinkingEnabled) {
      // DeepSeek thinking/reasoning mode does not accept temperature: 0; omit temperature cleanly.
      if (!isReasonerModel) {
        body.thinking = { type: 'enabled' };
      }
    } else {
      const effectiveTemp = temperature === undefined || temperature === null ? 0 : temperature;
      if (typeof effectiveTemp !== 'number' || !Number.isFinite(effectiveTemp) || effectiveTemp < 0 || effectiveTemp > 2) {
        throw createAdapterError(
          'ERR_INVALID_TEMPERATURE',
          `DeepSeek temperature must be a finite number in [0, 2], got ${String(temperature)}`
        );
      }
      body.temperature = effectiveTemp;
      if (thinkingMode === false) {
        body.thinking = { type: 'disabled' };
      }
    }

    if (responseFormat && typeof responseFormat === 'object') {
      body.response_format = responseFormat;
    }

    return {
      path: '/v1/chat/completions',
      body,
      expectedCount: 1
    };
  },

  parseResponse({ purpose, payload, fallbackInputTokens = 0, expectJson = undefined }) {
    if (purpose !== 'distill' && purpose !== 'judge') {
      throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `DeepSeek adapter does not support purpose=${purpose}`);
    }
    if (!payload || typeof payload !== 'object' || !Array.isArray(payload.choices) || payload.choices.length === 0) {
      throw createAdapterError(
        purpose === 'judge' ? 'ERR_PROVIDER_INVALID_JUDGE' : 'ERR_PROVIDER_INVALID_DISTILL',
        `Missing choices in DeepSeek ${purpose} response`
      );
    }
    const choice = payload.choices[0];
    const message = choice?.message;
    if (!message || typeof message.content !== 'string') {
      throw createAdapterError(
        purpose === 'judge' ? 'ERR_PROVIDER_INVALID_JUDGE' : 'ERR_PROVIDER_INVALID_DISTILL',
        `Missing message.content string in DeepSeek ${purpose} response`
      );
    }

    const requireStructuredJson = purpose === 'judge' ? expectJson !== false : expectJson === true;
    let parsedJson = null;
    if (requireStructuredJson) {
      parsedJson = parseStrictJsonObject(message.content, purpose);
    } else {
      try {
        const candidate = JSON.parse(message.content.trim());
        if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
          parsedJson = candidate;
        }
      } catch {
        parsedJson = null;
      }
    }

    return {
      purpose,
      content: message.content,
      parsedJson,
      reasoningContent: typeof message.reasoning_content === 'string' ? message.reasoning_content : null,
      finishReason: choice.finish_reason || null,
      usage: extractStandardUsage(payload, {
        fallbackInputTokens,
        completionIncludesReasoning: true
      })
    };
  }
});
