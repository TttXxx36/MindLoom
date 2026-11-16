export const MAX_EMBED_BATCH_SIZE = 32;

export function createAdapterError(code, message, extra = {}) {
  const err = new Error(`[${code}] ${message}`);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

export function validateTokenCount(val, fallback = 0, label = 'tokens') {
  if (val === undefined || val === null) {
    return fallback;
  }
  if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
    throw createAdapterError(
      'ERR_PROVIDER_INVALID_USAGE',
      `Invalid ${label} in provider usage payload: ${String(val)}`
    );
  }
  return val;
}

export function extractStandardUsage(payload, { fallbackInputTokens = 0, completionIncludesReasoning = true } = {}) {
  const usage = payload?.usage || {};
  const actualInputTokens = validateTokenCount(
    usage.prompt_tokens ?? usage.input_tokens,
    fallbackInputTokens,
    'prompt_tokens'
  );
  const actualOutputTokens = validateTokenCount(
    usage.completion_tokens ?? usage.output_tokens,
    0,
    'completion_tokens'
  );
  const actualReasoningTokens = validateTokenCount(
    usage.completion_tokens_details?.reasoning_tokens ?? usage.reasoning_tokens,
    0,
    'reasoning_tokens'
  );
  return {
    actualInputTokens,
    actualOutputTokens,
    actualReasoningTokens,
    billableOutputTokens: completionIncludesReasoning
      ? actualOutputTokens
      : actualOutputTokens + actualReasoningTokens,
    completionIncludesReasoning
  };
}

export function buildOpenAiEmbeddingRequest({ model, inputs, maxBatchSize = MAX_EMBED_BATCH_SIZE }) {
  if (typeof model !== 'string' || model.trim().length === 0) {
    throw createAdapterError('ERR_INVALID_MODEL', 'model must be a non-empty string');
  }
  const cleanModel = model.trim();
  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw createAdapterError('ERR_INVALID_EMBED_INPUT', 'inputs must be a non-empty array of strings');
  }
  if (!Number.isSafeInteger(maxBatchSize) || maxBatchSize <= 0) {
    throw createAdapterError('ERR_INVALID_BATCH_LIMIT', 'maxBatchSize must be a positive safe integer');
  }
  if (inputs.length > maxBatchSize) {
    throw createAdapterError(
      'ERR_EMBED_BATCH_LIMIT_EXCEEDED',
      `Embedding batch size ${inputs.length} exceeds limit ${maxBatchSize}`
    );
  }
  const cleanInputs = inputs.map((item, idx) => {
    if (typeof item !== 'string' || item.length === 0) {
      throw createAdapterError(
        'ERR_INVALID_EMBED_INPUT',
        `inputs[${idx}] must be a non-empty string`
      );
    }
    return item;
  });

  return {
    path: '/v1/embeddings',
    body: {
      model: cleanModel,
      input: cleanInputs,
      encoding_format: 'float'
    },
    expectedCount: cleanInputs.length
  };
}

export function parseOpenAiEmbeddingResponse({ payload, expectedCount, expectedDimension = null, fallbackInputTokens = 0 }) {
  if (!payload || typeof payload !== 'object') {
    throw createAdapterError('ERR_PROVIDER_INVALID_JSON', 'Provider response is not an object');
  }
  const data = payload.data;
  if (!Array.isArray(data) || data.length !== expectedCount) {
    throw createAdapterError(
      'ERR_PROVIDER_INVALID_EMBEDDING',
      `Expected ${expectedCount} embeddings, got ${Array.isArray(data) ? data.length : 'non-array'}`
    );
  }

  const orderedVectors = new Array(expectedCount);
  const seenIndices = new Set();
  let dimension = expectedDimension;

  for (const entry of data) {
    if (!entry || typeof entry !== 'object') {
      throw createAdapterError('ERR_PROVIDER_INVALID_EMBEDDING', 'Embedding entry must be an object');
    }
    const idx = entry.index;
    if (!Number.isInteger(idx) || idx < 0 || idx >= expectedCount) {
      throw createAdapterError(
        'ERR_PROVIDER_INVALID_EMBEDDING',
        `Embedding index out of bounds [0..${expectedCount - 1}]: ${String(idx)}`
      );
    }
    if (seenIndices.has(idx)) {
      throw createAdapterError('ERR_PROVIDER_INVALID_EMBEDDING', `Duplicate embedding index: ${idx}`);
    }
    seenIndices.add(idx);

    const vec = entry.embedding;
    if (!Array.isArray(vec) || vec.length === 0) {
      throw createAdapterError('ERR_PROVIDER_INVALID_EMBEDDING', `Empty embedding vector at index ${idx}`);
    }
    if (dimension === null) {
      dimension = vec.length;
    } else if (vec.length !== dimension) {
      throw createAdapterError(
        'ERR_PROVIDER_INVALID_EMBEDDING',
        `Embedding dimension mismatch at index ${idx}: expected ${dimension}, got ${vec.length}`
      );
    }
    for (let j = 0; j < vec.length; j++) {
      if (typeof vec[j] !== 'number' || !Number.isFinite(vec[j])) {
        throw createAdapterError(
          'ERR_PROVIDER_INVALID_EMBEDDING',
          `Non-finite embedding value at [${idx}][${j}]`
        );
      }
    }
    orderedVectors[idx] = vec;
  }

  if (seenIndices.size !== expectedCount) {
    throw createAdapterError('ERR_PROVIDER_INVALID_EMBEDDING', 'Incomplete embedding indices');
  }

  return {
    vectors: orderedVectors,
    dimension,
    usage: extractStandardUsage(payload, {
      fallbackInputTokens,
      completionIncludesReasoning: true
    })
  };
}
