import crypto from 'node:crypto';
import { getAdapterForPurpose } from './adapters/index.mjs';
import {
  isProductionCliRuntime,
  reserveCloudEgressBudget,
  recheckApprovalBeforeSend,
  releasePrecheckFailedReservation,
  settleCloudEgressUsage,
  retainCloudEgressReservation
} from '../security/cloud-approvals.mjs';
import { assertRealCloudApiGate } from '../security/isolation-sentinel.mjs';
import { formatSafeErrorForExitB } from '../security/sanitizer.mjs';

const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);

function createGatewayError(code, message, extra = {}) {
  const err = new Error(`[${code}] ${message}`);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

export function isLoopbackHostname(hostname) {
  return LOOPBACK_HOSTNAMES.has(String(hostname || '').trim().toLowerCase());
}

export function validateGatewayEndpoint({
  baseUrl,
  testContext = false,
  sentinelReport = null
}) {
  if (typeof baseUrl !== 'string' || baseUrl.trim().length === 0) {
    throw createGatewayError('ERR_INVALID_ENDPOINT', 'Gateway baseUrl must be a non-empty string');
  }
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw createGatewayError('ERR_INVALID_ENDPOINT', `Malformed gateway baseUrl: ${baseUrl}`);
  }

  if (parsed.username || parsed.password) {
    throw createGatewayError(
      'ERR_ENDPOINT_CREDENTIALS_FORBIDDEN',
      'Embedded URL credentials are forbidden; pass API key only via Authorization header'
    );
  }

  const loopback = isLoopbackHostname(parsed.hostname);
  if (loopback) {
    if (isProductionCliRuntime()) {
      throw createGatewayError(
        'ERR_LOOPBACK_FORBIDDEN_IN_PROD',
        'Loopback mock endpoints are strictly forbidden in production CLI runtime'
      );
    }
    if (testContext !== true) {
      throw createGatewayError(
        'ERR_LOOPBACK_REQUIRES_TEST_CONTEXT',
        'Loopback endpoints require explicit testContext === true'
      );
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw createGatewayError(
        'ERR_INVALID_PROTOCOL',
        `Unsupported loopback protocol: ${parsed.protocol}`
      );
    }
    return {
      url: parsed,
      isLoopbackMock: true,
      baseOriginAndPath: parsed.toString().replace(/\/+$/, '')
    };
  }

  if (parsed.protocol !== 'https:') {
    throw createGatewayError(
      'ERR_HTTPS_REQUIRED',
      `External cloud endpoint must use https:// (got ${parsed.protocol})`
    );
  }

  // Real external cloud call MUST pass all 4 OS isolation sentinels
  assertRealCloudApiGate(sentinelReport);

  return {
    url: parsed,
    isLoopbackMock: false,
    baseOriginAndPath: parsed.toString().replace(/\/+$/, '')
  };
}

function resolveTargetEndpointUrl(baseOriginAndPath, adapterPath) {
  if (baseOriginAndPath.endsWith(adapterPath)) {
    return baseOriginAndPath;
  }
  if (adapterPath.startsWith('/v1/') && baseOriginAndPath.endsWith('/v1')) {
    return `${baseOriginAndPath}${adapterPath.slice(3)}`;
  }
  return `${baseOriginAndPath}${adapterPath}`;
}

function isAcceptedEndpointPathname(pathname, adapter, purpose, fallbackPath) {
  const cleanPath = String(pathname || '').replace(/\/+$/, '') || '/';
  const accepted = typeof adapter.getAcceptedEndpointPaths === 'function'
    ? adapter.getAcceptedEndpointPaths(purpose)
    : [fallbackPath];
  return accepted.some((p) => cleanPath === p || cleanPath.endsWith(p));
}

function isAbortOrTimeoutError(err) {
  if (!err) return false;
  const check = (e) =>
    Boolean(
      e &&
        (e.name === 'AbortError' ||
          e.name === 'TimeoutError' ||
          e.code === 'ABORT_ERR' ||
          e.code === 'UND_ERR_HEADERS_TIMEOUT' ||
          e.code === 'UND_ERR_BODY_TIMEOUT')
    );
  return check(err) || check(err.cause);
}

function isConnectionRefusedError(err) {
  if (!err) return false;
  const code = err.code || err.cause?.code;
  return code === 'ECONNREFUSED';
}

export async function callCloudProviderGateway({
  operatorDb,
  cloudApprovalId = null,
  approvalId = null,
  runPlanId = null,
  runId = null,
  requestId = `req-${crypto.randomUUID()}`,
  preReserved = null,
  provider,
  modelId = null,
  model = null,
  purpose,
  baseUrl = null,
  endpointUrl = null,
  pricingVersion = null,
  requiresQueryEgress = null,
  apiKeyProvider,
  vaultId,
  dataId,
  payloadInput,
  reservedInputTokens,
  maxOutputTokens = null,
  expectedDimension = null,
  expectJson = undefined,
  overallDeadlineMs = 4000,
  testContext = false,
  sentinelReport = null,
  fetchFn = globalThis.fetch
}) {
  if (!operatorDb) {
    throw createGatewayError('ERR_OPERATOR_DB_REQUIRED', 'operatorDb is required');
  }
  if (typeof fetchFn !== 'function') {
    throw createGatewayError('ERR_FETCH_UNAVAILABLE', 'fetch implementation is required');
  }

  const resolvedApprovalId = cloudApprovalId || approvalId || preReserved?.cloudApprovalId;
  const resolvedRunPlanId = runPlanId || runId || preReserved?.runPlanId || `run-${crypto.randomUUID()}`;
  const resolvedModelId = modelId || model;
  const hasExplicitEndpointUrl = typeof endpointUrl === 'string' && endpointUrl.trim().length > 0;
  const rawUrlInput = hasExplicitEndpointUrl ? endpointUrl : baseUrl;

  const releasePreReservedOnPrecheckError = () => {
    if (preReserved?.requestId) {
      try {
        releasePrecheckFailedReservation(operatorDb, { requestId: preReserved.requestId });
      } catch {
        // Ignore if already released/settled
      }
    }
  };

  let endpoint;
  let adapter;
  let built;
  let targetUrl;
  let effectiveReserveMaxOutputTokens;
  try {
    if (preReserved && resolvedApprovalId && preReserved.cloudApprovalId !== resolvedApprovalId) {
      throw createGatewayError(
        'ERR_APPROVAL_MISMATCH',
        `preReserved cloudApprovalId (${preReserved.cloudApprovalId}) != ${resolvedApprovalId}`
      );
    }
    endpoint = validateGatewayEndpoint({ baseUrl: rawUrlInput, testContext, sentinelReport });
    adapter = getAdapterForPurpose({ provider, purpose });
    const adapterInput = {
      purpose,
      model: resolvedModelId,
      ...(payloadInput || {})
    };
    if (
      adapterInput.maxTokens === undefined &&
      maxOutputTokens !== null &&
      maxOutputTokens !== undefined &&
      (purpose === 'distill' || purpose === 'judge')
    ) {
      adapterInput.maxTokens = maxOutputTokens;
    }
    built = adapter.buildRequest(adapterInput);
    if (
      typeof built.body?.max_tokens === 'number' &&
      maxOutputTokens !== null &&
      maxOutputTokens !== undefined &&
      built.body.max_tokens > maxOutputTokens
    ) {
      throw createGatewayError(
        'ERR_OUTPUT_TOKENS_PER_CALL_EXCEEDED',
        `Request max_tokens (${built.body.max_tokens}) exceeds maxOutputTokens (${maxOutputTokens})`
      );
    }
    effectiveReserveMaxOutputTokens =
      typeof built.body?.max_tokens === 'number' ? built.body.max_tokens : maxOutputTokens;
    if (
      preReserved &&
      typeof built.body?.max_tokens === 'number' &&
      built.body.max_tokens > (preReserved.reservedOutputTokens ?? 0)
    ) {
      throw createGatewayError(
        'ERR_OUTPUT_TOKENS_PER_CALL_EXCEEDED',
        `Request max_tokens (${built.body.max_tokens}) exceeds pre-reserved output tokens (${preReserved.reservedOutputTokens ?? 0})`
      );
    }
    if (hasExplicitEndpointUrl) {
      if (!isAcceptedEndpointPathname(endpoint.url.pathname, adapter, purpose, built.path)) {
        throw createGatewayError(
          'ERR_INVALID_ENDPOINT',
          `Endpoint URL path ${endpoint.url.pathname} is not valid for ${provider}/${purpose}`
        );
      }
      targetUrl = endpoint.baseOriginAndPath;
    } else {
      targetUrl = resolveTargetEndpointUrl(endpoint.baseOriginAndPath, built.path);
    }
  } catch (err) {
    releasePreReservedOnPrecheckError();
    throw err;
  }

  const parsedDeadline = Number(overallDeadlineMs);
  const effectiveDeadlineMs = Number.isFinite(parsedDeadline) ? parsedDeadline : 4000;
  const deadlineAt = Date.now() + effectiveDeadlineMs;
  const bodyJson = JSON.stringify(built.body);
  const egressBytes = Buffer.byteLength(bodyJson, 'utf8');

  const attemptIds = [];
  let currentReservation = preReserved;
  if (!currentReservation) {
    currentReservation = reserveCloudEgressBudget(operatorDb, {
      cloudApprovalId: resolvedApprovalId,
      runPlanId: resolvedRunPlanId,
      requestId,
      parentRequestId: null,
      attemptNo: 1,
      provider,
      modelId: resolvedModelId,
      purpose,
      endpointUrl: targetUrl,
      pricingVersion,
      requiresQueryEgress,
      reservedInputTokens,
      maxOutputTokens: effectiveReserveMaxOutputTokens,
      vaultId,
      dataId
    });
  }

  const maxAttempts = 2; // Initial + at most 1 retry for 429 or pure ECONNREFUSED
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const activeRequestId = currentReservation.requestId;
    attemptIds.push(activeRequestId);

    const remainingBeforeSend = deadlineAt - Date.now();
    if (remainingBeforeSend <= 0) {
      releasePrecheckFailedReservation(operatorDb, { requestId: activeRequestId });
      throw createGatewayError('ERR_DEADLINE_EXCEEDED', 'Overall deadline exhausted before send', {
        attemptIds
      });
    }

    const precheck = recheckApprovalBeforeSend(operatorDb, {
      cloudApprovalId: resolvedApprovalId,
      requestId: activeRequestId,
      provider,
      modelId: resolvedModelId,
      purpose,
      endpointUrl: targetUrl,
      pricingVersion,
      requiresQueryEgress,
      vaultId,
      dataId
    });
    if (!precheck.allowed) {
      throw createGatewayError(precheck.code, precheck.reason, {
        attemptIds,
        precheckFailed: true
      });
    }

    const apiKey = typeof apiKeyProvider === 'function' ? apiKeyProvider() : apiKeyProvider;
    if (typeof apiKey !== 'string' || apiKey.trim().length === 0) {
      releasePrecheckFailedReservation(operatorDb, { requestId: activeRequestId });
      throw createGatewayError('ERR_MISSING_API_KEY', 'Cloud API key is unavailable', {
        attemptIds
      });
    }

    const attemptStartMs = performance.now();
    let response;
    try {
      const timeoutSignal = AbortSignal.timeout(Math.max(10, remainingBeforeSend));
      response = await fetchFn(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey.trim()}`
        },
        body: bodyJson,
        redirect: 'error',
        signal: timeoutSignal
      });
    } catch (fetchErr) {
      const latencyMs = Math.max(0, performance.now() - attemptStartMs);
      const safeMsg = formatSafeErrorForExitB(fetchErr);

      if (isAbortOrTimeoutError(fetchErr)) {
        retainCloudEgressReservation(operatorDb, {
          requestId: activeRequestId,
          state: 'retained_on_timeout',
          outcome: 'timeout',
          egressBytes,
          latencyMs
        });
        throw createGatewayError(
          'ERR_GATEWAY_TIMEOUT',
          `Gateway request timed out/aborted (reservation retained, purpose=${purpose}, timeoutMs=${effectiveDeadlineMs}, elapsedMs=${Math.round(latencyMs)}): ${safeMsg}`,
          { attemptIds, retainedRequestId: activeRequestId, purpose, timeoutMs: effectiveDeadlineMs, elapsedMs: Math.round(latencyMs) }
        );
      }

      // Pure TCP ECONNREFUSED sends 0 HTTP bytes -> safe to release as precheck_failed
      if (isConnectionRefusedError(fetchErr)) {
        releasePrecheckFailedReservation(operatorDb, { requestId: activeRequestId });
        if (attempt < maxAttempts && deadlineAt - Date.now() > 25) {
          const retryRequestId = `req-${crypto.randomUUID()}`;
          try {
            currentReservation = reserveCloudEgressBudget(operatorDb, {
              cloudApprovalId: resolvedApprovalId,
              runPlanId: resolvedRunPlanId,
              requestId: retryRequestId,
              parentRequestId: attemptIds[0],
              attemptNo: attempt + 1,
              provider,
              modelId: resolvedModelId,
              purpose,
              endpointUrl: targetUrl,
              pricingVersion,
              requiresQueryEgress,
              reservedInputTokens,
              maxOutputTokens: effectiveReserveMaxOutputTokens,
              vaultId,
              dataId
            });
            continue;
          } catch {
            // Remaining budget/approval unavailable for retry; surface original network error
          }
        }
        throw createGatewayError('ERR_GATEWAY_NETWORK', `Gateway connection refused: ${safeMsg}`, {
          attemptIds
        });
      }

      // Redirect blocked by fetch(redirect: 'error') occurred after outbound request received 3xx
      const isRedirectLike = /redirect/i.test(
        String(fetchErr?.message || '') + String(fetchErr?.cause?.message || '')
      );
      if (isRedirectLike) {
        settleCloudEgressUsage(operatorDb, {
          requestId: activeRequestId,
          actualInputTokens: 0,
          actualOutputTokens: 0,
          httpStatus: 302,
          egressBytes,
          latencyMs,
          outcome: 'http_error'
        });
        throw createGatewayError('ERR_REDIRECT_BLOCKED', `HTTP redirect forbidden: ${safeMsg}`, {
          attemptIds
        });
      }

      retainCloudEgressReservation(operatorDb, {
        requestId: activeRequestId,
        state: 'retained_on_unknown_bill',
        outcome: 'http_error',
        egressBytes,
        latencyMs
      });
      throw createGatewayError('ERR_GATEWAY_NETWORK', `Gateway network error: ${safeMsg}`, {
        attemptIds,
        retainedRequestId: activeRequestId
      });
    }

    const latencyMs = Math.max(0, performance.now() - attemptStartMs);
    const status = Number(response.status);

    if (status >= 300 && status < 400) {
      await response.body?.cancel?.().catch(() => {});
      settleCloudEgressUsage(operatorDb, {
        requestId: activeRequestId,
        actualInputTokens: 0,
        actualOutputTokens: 0,
        httpStatus: status,
        egressBytes,
        latencyMs,
        outcome: 'http_error'
      });
      throw createGatewayError(
        'ERR_REDIRECT_BLOCKED',
        `HTTP ${status} redirect rejected (0 retries)`,
        { attemptIds, httpStatus: status }
      );
    }

    if (status === 401 || status === 402 || status === 403) {
      await response.body?.cancel?.().catch(() => {});
      settleCloudEgressUsage(operatorDb, {
        requestId: activeRequestId,
        actualInputTokens: 0,
        actualOutputTokens: 0,
        httpStatus: status,
        egressBytes,
        latencyMs,
        outcome: 'http_error'
      });
      throw createGatewayError(
        'ERR_CLOUD_AUTH_OR_QUOTA',
        `Provider rejected with HTTP ${status} (0 retries, fallback to Mode 0)`,
        { attemptIds, httpStatus: status, retryable: false }
      );
    }

    if (status === 429) {
      await response.body?.cancel?.().catch(() => {});
      settleCloudEgressUsage(operatorDb, {
        requestId: activeRequestId,
        actualInputTokens: 0,
        actualOutputTokens: 0,
        httpStatus: 429,
        egressBytes,
        latencyMs,
        outcome: 'http_error'
      });
      lastError = createGatewayError('ERR_HTTP_429', 'Rate limited (HTTP 429)', {
        attemptIds,
        httpStatus: 429
      });
      if (attempt < maxAttempts && deadlineAt - Date.now() > 25) {
        const retryRequestId = `req-${crypto.randomUUID()}`;
        try {
          currentReservation = reserveCloudEgressBudget(operatorDb, {
            cloudApprovalId: resolvedApprovalId,
            runPlanId: resolvedRunPlanId,
            requestId: retryRequestId,
            parentRequestId: attemptIds[0],
            attemptNo: attempt + 1,
            provider,
            modelId: resolvedModelId,
            purpose,
            endpointUrl: targetUrl,
            pricingVersion,
            requiresQueryEgress,
            reservedInputTokens,
            maxOutputTokens: effectiveReserveMaxOutputTokens,
            vaultId,
            dataId
          });
          continue;
        } catch {
          // Remaining budget/approval unavailable for soft retry -> throw ERR_HTTP_429
        }
      }
      throw lastError;
    }

    if (status < 200 || status >= 300) {
      let errJson = null;
      try {
        const txt = await response.text();
        if (txt && txt.trim().length > 0) {
          errJson = JSON.parse(txt);
        }
      } catch (textErr) {
        if (isAbortOrTimeoutError(textErr)) {
          const textLatencyMs = Math.max(0, performance.now() - attemptStartMs);
          retainCloudEgressReservation(operatorDb, {
            requestId: activeRequestId,
            state: 'retained_on_timeout',
            outcome: 'timeout',
            httpStatus: status,
            egressBytes,
            latencyMs: textLatencyMs
          });
          throw createGatewayError(
            'ERR_GATEWAY_TIMEOUT',
            `Gateway error response body timed out (reservation retained, purpose=${purpose}, timeoutMs=${effectiveDeadlineMs}, elapsedMs=${Math.round(textLatencyMs)}): ${formatSafeErrorForExitB(textErr)}`,
            { attemptIds, httpStatus: status, retainedRequestId: activeRequestId, purpose, timeoutMs: effectiveDeadlineMs, elapsedMs: Math.round(textLatencyMs) }
          );
        }
        errJson = null;
      }
      const uncertainUpstream = status === 504 || (status >= 500 && !errJson);
      if (uncertainUpstream) {
        retainCloudEgressReservation(operatorDb, {
          requestId: activeRequestId,
          state: 'retained_on_unknown_bill',
          outcome: 'http_error',
          httpStatus: status,
          egressBytes,
          latencyMs
        });
      } else {
        settleCloudEgressUsage(operatorDb, {
          requestId: activeRequestId,
          actualInputTokens: 0,
          actualOutputTokens: 0,
          httpStatus: status,
          egressBytes,
          latencyMs,
          outcome: 'http_error'
        });
      }
      throw createGatewayError('ERR_HTTP_UPSTREAM', `Provider HTTP ${status}`, {
        attemptIds,
        httpStatus: status
      });
    }

    let rawJson;
    try {
      rawJson = await response.json();
    } catch (jsonErr) {
      const bodyLatencyMs = Math.max(0, performance.now() - attemptStartMs);
      if (isAbortOrTimeoutError(jsonErr)) {
        retainCloudEgressReservation(operatorDb, {
          requestId: activeRequestId,
          state: 'retained_on_timeout',
          outcome: 'timeout',
          httpStatus: status,
          egressBytes,
          latencyMs: bodyLatencyMs
        });
        throw createGatewayError(
          'ERR_GATEWAY_TIMEOUT',
          `Gateway response body timed out (reservation retained, purpose=${purpose}, timeoutMs=${effectiveDeadlineMs}, elapsedMs=${Math.round(bodyLatencyMs)}): ${formatSafeErrorForExitB(jsonErr)}`,
          { attemptIds, httpStatus: status, retainedRequestId: activeRequestId, purpose, timeoutMs: effectiveDeadlineMs, elapsedMs: Math.round(bodyLatencyMs) }
        );
      }
      retainCloudEgressReservation(operatorDb, {
        requestId: activeRequestId,
        state: 'retained_on_unknown_bill',
        outcome: 'invalid_response',
        httpStatus: status,
        egressBytes,
        latencyMs: bodyLatencyMs
      });
      throw createGatewayError('ERR_PROVIDER_INVALID_JSON', 'Invalid JSON body from provider', {
        attemptIds,
        httpStatus: status,
        retainedRequestId: activeRequestId
      });
    }

    let parsed;
    try {
      parsed = adapter.parseResponse({
        purpose,
        payload: rawJson,
        expectedCount: built.expectedCount,
        expectedDimension,
        fallbackInputTokens: reservedInputTokens,
        expectJson
      });
    } catch (parseErr) {
      const parseLatencyMs = Math.max(0, performance.now() - attemptStartMs);
      const usageIn = rawJson?.usage?.prompt_tokens ?? rawJson?.usage?.input_tokens;
      const usageOut = rawJson?.usage?.completion_tokens ?? rawJson?.usage?.output_tokens ?? 0;
      const hasKnownZeroOutputUsage =
        (currentReservation.reservedOutputTokens || 0) === 0 &&
        typeof usageIn === 'number' &&
        Number.isSafeInteger(usageIn) &&
        usageIn >= 0 &&
        typeof usageOut === 'number' &&
        Number.isSafeInteger(usageOut) &&
        usageOut === 0;

      if (hasKnownZeroOutputUsage) {
        settleCloudEgressUsage(operatorDb, {
          requestId: activeRequestId,
          actualInputTokens: usageIn,
          actualOutputTokens: 0,
          httpStatus: status,
          egressBytes,
          latencyMs: parseLatencyMs,
          outcome: 'invalid_response'
        });
      } else {
        retainCloudEgressReservation(operatorDb, {
          requestId: activeRequestId,
          state: 'retained_on_unknown_bill',
          outcome: 'invalid_response',
          httpStatus: status,
          egressBytes,
          latencyMs: parseLatencyMs
        });
      }
      throw parseErr;
    }

    const finalLatencyMs = Math.max(0, performance.now() - attemptStartMs);
    const settlement = settleCloudEgressUsage(operatorDb, {
      requestId: activeRequestId,
      actualInputTokens: parsed.usage.actualInputTokens,
      actualOutputTokens: parsed.usage.actualOutputTokens,
      actualReasoningTokens: parsed.usage.actualReasoningTokens,
      completionIncludesReasoning: parsed.usage.completionIncludesReasoning,
      httpStatus: status,
      egressBytes,
      latencyMs: finalLatencyMs,
      outcome: 'ok'
    });

    return {
      ok: true,
      provider,
      modelId: resolvedModelId,
      purpose,
      runPlanId: resolvedRunPlanId,
      requestId: activeRequestId,
      attemptIds,
      httpStatus: status,
      egressBytes,
      latencyMs: finalLatencyMs,
      parsed,
      settlement
    };
  }

  throw lastError || createGatewayError('ERR_GATEWAY_EXHAUSTED', 'Gateway retries exhausted', { attemptIds });
}
