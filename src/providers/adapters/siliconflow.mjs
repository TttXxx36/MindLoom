import {
  MAX_EMBED_BATCH_SIZE,
  createAdapterError,
  extractStandardUsage,
  buildOpenAiEmbeddingRequest,
  parseOpenAiEmbeddingResponse
} from './openai-embedding-common.mjs';

export { extractStandardUsage, MAX_EMBED_BATCH_SIZE };

export const siliconflowAdapter = Object.freeze({
  provider: 'siliconflow',
  supportedPurposes: Object.freeze(['embed_doc', 'embed_query', 'rerank']),
  completionIncludesReasoning: true,
  maxEmbedBatchSize: MAX_EMBED_BATCH_SIZE,

  getEndpointPath(purpose) {
    if (purpose === 'embed_query' || purpose === 'embed_doc') {
      return '/v1/embeddings';
    }
    if (purpose === 'rerank') {
      return '/v1/rerank';
    }
    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `SiliconFlow adapter does not support purpose=${purpose}`);
  },

  getAcceptedEndpointPaths(purpose) {
    if (purpose === 'embed_query' || purpose === 'embed_doc') {
      return ['/v1/embeddings', '/embeddings'];
    }
    if (purpose === 'rerank') {
      return ['/v1/rerank', '/rerank'];
    }
    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `SiliconFlow adapter does not support purpose=${purpose}`);
  },

  buildRequest({ purpose, model, inputs, query, documents, topN = null, maxBatchSize = MAX_EMBED_BATCH_SIZE }) {
    if (purpose === 'embed_query' || purpose === 'embed_doc') {
      return buildOpenAiEmbeddingRequest({ model, inputs, maxBatchSize });
    }

    if (typeof model !== 'string' || model.trim().length === 0) {
      throw createAdapterError('ERR_INVALID_MODEL', 'model must be a non-empty string');
    }
    const cleanModel = model.trim();

    if (purpose === 'rerank') {
      if (typeof query !== 'string' || query.trim().length === 0) {
        throw createAdapterError('ERR_INVALID_RERANK_QUERY', 'rerank query must be a non-empty string');
      }
      if (!Array.isArray(documents) || documents.length === 0) {
        throw createAdapterError('ERR_INVALID_RERANK_DOCS', 'rerank documents must be a non-empty array');
      }
      if (topN !== null && topN !== undefined && (!Number.isSafeInteger(topN) || topN <= 0)) {
        throw createAdapterError('ERR_INVALID_RERANK_TOP_N', `topN must be a positive safe integer, got ${String(topN)}`);
      }
      // Strictly send pure sanitized text strings; zero UUIDs or paths!
      const cleanDocuments = documents.map((d) => {
        if (typeof d !== 'string') {
          throw createAdapterError('ERR_INVALID_RERANK_DOCS', 'rerank documents must be plain strings');
        }
        return d;
      });
      return {
        path: '/v1/rerank',
        body: {
          model: cleanModel,
          query,
          documents: cleanDocuments,
          top_n: topN ?? cleanDocuments.length,
          return_documents: false
        },
        expectedCount: cleanDocuments.length
      };
    }

    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `SiliconFlow adapter does not support purpose=${purpose}`);
  },

  parseResponse({ purpose, payload, expectedCount, expectedDimension = null, fallbackInputTokens = 0 }) {
    if (purpose === 'embed_query' || purpose === 'embed_doc') {
      return parseOpenAiEmbeddingResponse({
        payload,
        expectedCount,
        expectedDimension,
        fallbackInputTokens
      });
    }

    if (!payload || typeof payload !== 'object') {
      throw createAdapterError('ERR_PROVIDER_INVALID_JSON', 'Provider response is not an object');
    }

    if (purpose === 'rerank') {
      const results = payload.results;
      if (!Array.isArray(results) || results.length === 0) {
        throw createAdapterError(
          'ERR_PROVIDER_INVALID_RERANK',
          'Rerank response results must be a non-empty array'
        );
      }

      const ranked = [];
      const seen = new Set();
      for (const item of results) {
        if (!item || typeof item !== 'object') {
          throw createAdapterError('ERR_PROVIDER_INVALID_RERANK', 'Rerank result entry must be an object');
        }
        const idx = item.index;
        if (!Number.isInteger(idx) || idx < 0 || idx >= expectedCount) {
          throw createAdapterError(
            'ERR_PROVIDER_INVALID_RERANK',
            `Rerank index out of bounds [0..${expectedCount - 1}]: ${String(idx)}`
          );
        }
        if (seen.has(idx)) {
          throw createAdapterError('ERR_PROVIDER_INVALID_RERANK', `Duplicate rerank index: ${idx}`);
        }
        const score = item.relevance_score ?? item.score;
        if (typeof score !== 'number' || !Number.isFinite(score)) {
          throw createAdapterError(
            'ERR_PROVIDER_INVALID_RERANK',
            `Non-finite rerank relevance_score at index ${idx}: ${String(score)}`
          );
        }
        seen.add(idx);
        ranked.push({ index: idx, score });
      }

      // Sort by relevance_score descending (preserving provider order on ties) and preserve partial subset tail order
      const sortedRanked = [...ranked].sort((a, b) => b.score - a.score);
      const orderedIndices = sortedRanked.map((r) => r.index);
      for (let i = 0; i < expectedCount; i++) {
        if (!seen.has(i)) {
          orderedIndices.push(i);
        }
      }

      return {
        ranked: sortedRanked,
        orderedIndices,
        usage: extractStandardUsage(payload, {
          fallbackInputTokens,
          completionIncludesReasoning: true
        })
      };
    }

    throw createAdapterError('ERR_UNSUPPORTED_PURPOSE', `SiliconFlow adapter does not support purpose=${purpose}`);
  }
});
