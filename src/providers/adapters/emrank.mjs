import {
  MAX_EMBED_BATCH_SIZE,
  createAdapterError,
  buildOpenAiEmbeddingRequest,
  parseOpenAiEmbeddingResponse
} from './openai-embedding-common.mjs';

/**
 * EMRank (https://emrank.tech/v1/embeddings) OpenAI-compatible Embedding adapter.
 */
export const emrankAdapter = Object.freeze({
  provider: 'emrank',
  supportedPurposes: Object.freeze(['embed_doc', 'embed_query']),
  completionIncludesReasoning: true,
  maxEmbedBatchSize: MAX_EMBED_BATCH_SIZE,

  getEndpointPath(purpose) {
    if (purpose === 'embed_query' || purpose === 'embed_doc') {
      return '/v1/embeddings';
    }
    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `EMRank adapter does not support purpose=${purpose}`);
  },

  getAcceptedEndpointPaths(purpose) {
    if (purpose === 'embed_query' || purpose === 'embed_doc') {
      return ['/v1/embeddings', '/embeddings'];
    }
    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `EMRank adapter does not support purpose=${purpose}`);
  },

  buildRequest({ purpose, model, inputs, maxBatchSize = MAX_EMBED_BATCH_SIZE }) {
    if (purpose !== 'embed_query' && purpose !== 'embed_doc') {
      throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `EMRank adapter does not support purpose=${purpose}`);
    }
    return buildOpenAiEmbeddingRequest({ model, inputs, maxBatchSize });
  },

  parseResponse({ purpose, payload, expectedCount, expectedDimension = null, fallbackInputTokens = 0 }) {
    if (purpose !== 'embed_query' && purpose !== 'embed_doc') {
      throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `EMRank adapter does not support purpose=${purpose}`);
    }
    return parseOpenAiEmbeddingResponse({
      payload,
      expectedCount,
      expectedDimension,
      fallbackInputTokens
    });
  }
});
