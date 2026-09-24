import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  scrubTelemetryFields,
  scrubTelemetryPayload,
  emitScrubbedTelemetry,
  TELEMETRY_REDACTION_VERSION,
} from './scrubTelemetryFields'

describe('scrubTelemetryFields', () => {
  it('preserves safe operational fields', () => {
    const input = {
      event: 'verify.success',
      level: 'info',
      request_id: 'req-1',
      duration_ms: 42,
      view: 'verify',
      tier: 'silent',
    }
    const result = scrubTelemetryFields(input)
    expect(result.data).toEqual(input)
    expect(result.redactionsApplied).toBe(0)
    expect(result.redactionVersion).toBe(TELEMETRY_REDACTION_VERSION)
  })

  it('redacts secrets, seeds, and tokens by key', () => {
    const result = scrubTelemetryFields({
      event: 'vault.unlock',
      token: 'ghp_supersecret',
      seed_phrase: 'abandon abandon abandon',
      password: 'hunter2',
      ok: true,
    })
    const data = result.data as Record<string, unknown>
    expect(data.event).toBe('vault.unlock')
    expect(data.ok).toBe(true)
    expect(data.token).toBe('[REDACTED:secret]')
    expect(data.seed_phrase).toBe('[REDACTED:secret]')
    expect(data.password).toBe('[REDACTED:secret]')
    expect(result.categoriesRedacted).toContain('secret')
  })

  it('redacts witness, media, and proof payloads', () => {
    const result = scrubTelemetryFields({
      witness_data: { a: 1 },
      video: 'AAAA...',
      proof_payload: { pi: [1, 2, 3] },
      nullifier: '0xabc',
      request_id: 'r2',
    })
    const data = result.data as Record<string, unknown>
    expect(data.witness_data).toBe('[REDACTED:witness]')
    expect(data.video).toBe('[REDACTED:media]')
    expect(data.proof_payload).toBe('[REDACTED:proof]')
    expect(data.nullifier).toBe('[REDACTED:proof]')
    expect(data.request_id).toBe('r2')
    expect(result.categoriesRedacted).toEqual(
      expect.arrayContaining(['witness', 'media', 'proof']),
    )
  })

  it('redacts wallet signatures and key material', () => {
    const result = scrubTelemetryFields({
      signature: 'ed25519...',
      signed_tx: 'AAAA...',
      xdr: 'envelope',
      component: 'wallet',
    })
    const data = result.data as Record<string, unknown>
    expect(data.signature).toBe('[REDACTED:wallet_sig]')
    expect(data.signed_tx).toBe('[REDACTED:wallet_sig]')
    expect(data.xdr).toBe('[REDACTED:wallet_sig]')
    expect(data.component).toBe('wallet')
  })

  it('redacts PII fields', () => {
    const result = scrubTelemetryFields({
      email: 'user@example.com',
      client_ip: '1.2.3.4',
      event: 'auth.fail',
    })
    const data = result.data as Record<string, unknown>
    expect(data.email).toBe('[REDACTED:pii]')
    expect(data.client_ip).toBe('[REDACTED:pii]')
    expect(data.event).toBe('auth.fail')
  })

  it('redacts long hex/base64 blobs even under safe-looking keys', () => {
    const hex = 'ab'.repeat(40)
    const result = scrubTelemetryFields({ note: hex, event: 'debug' })
    const data = result.data as Record<string, unknown>
    expect(data.note).toBe('[REDACTED:secret]')
    expect(data.event).toBe('debug')
  })

  it('truncates oversized string values', () => {
    const long = 'x'.repeat(400)
    const result = scrubTelemetryFields({ reason: long }, { capChars: 32 })
    const data = result.data as Record<string, unknown>
    expect(String(data.reason)).toMatch(/^x{32}…\[truncated\]$/)
    expect(result.truncationsApplied).toBe(1)
  })

  it('stops on excessive nesting (boundary)', () => {
    let nested: unknown = { leaf: 'ok' }
    for (let i = 0; i < 20; i++) nested = { child: nested }
    const result = scrubTelemetryFields(nested, { maxDepth: 4 })
    expect(result.stopped).toBe(true)
    expect(result.stopReason).toBe('max_depth')
  })

  it('stops on oversized object graphs (boundary)', () => {
    const big = Object.fromEntries(
      Array.from({ length: 50 }, (_, i) => [`k${i}`, { v: i }]),
    )
    const result = scrubTelemetryFields(big, { maxNodes: 10 })
    expect(result.stopped).toBe(true)
    expect(result.stopReason).toBe('max_nodes')
  })

  it('handles null, undefined, and primitive inputs', () => {
    expect(scrubTelemetryFields(null).data).toBeNull()
    expect(scrubTelemetryFields(undefined).data).toBeUndefined()
    expect(scrubTelemetryFields(7).data).toBe(7)
    expect(scrubTelemetryFields(true).data).toBe(true)
  })

  it('redacts ArrayBuffer / TypedArray media bytes', () => {
    const buf = new Uint8Array([1, 2, 3, 4]).buffer
    const result = scrubTelemetryFields({ payload: buf, event: 'upload' })
    const data = result.data as Record<string, unknown>
    expect(data.payload).toBe('[REDACTED:media]')
  })

  it('scrubTelemetryPayload returns data only', () => {
    expect(scrubTelemetryPayload({ token: 'x', ok: true })).toEqual({
      token: '[REDACTED:secret]',
      ok: true,
    })
  })

  it('is idempotent under re-scrub (regression)', () => {
    const once = scrubTelemetryFields({
      proof: 'secret-proof',
      request_id: 'abc',
    })
    const twice = scrubTelemetryFields(once.data)
    expect(twice.data).toEqual(once.data)
    // Marker strings are not reclassified as proof values under key "proof"
    // because the key still matches — redaction count may be >0, but payload stable.
    expect(twice.data).toEqual({
      proof: '[REDACTED:proof]',
      request_id: 'abc',
    })
  })
})

describe('emitScrubbedTelemetry', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('never forwards raw secrets to console.error', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    emitScrubbedTelemetry('error', 'boundary.catch', {
      message: 'boom',
      private_key: 'SXXXXXXXX',
      proof_data: { a: 1 },
    })
    expect(spy).toHaveBeenCalledTimes(1)
    const payload = spy.mock.calls[0][1] as Record<string, unknown>
    expect(payload.private_key).toBe('[REDACTED:secret]')
    expect(payload.proof_data).toBe('[REDACTED:proof]')
    expect(payload.event).toBe('boundary.catch')
    expect(JSON.stringify(payload)).not.toContain('SXXXXXXXX')
  })
})
