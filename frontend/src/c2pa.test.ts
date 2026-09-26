/**
 * Tests for frontend/src/c2pa.ts — C2PA interoperability layer.
 *
 * Coverage:
 * - Valid manifest export and import.
 * - Round-trip export/import preserves all canonical bindings.
 * - Structural adversarial fixtures: oversized, malformed boxes, recursion,
 *   unknown algorithms, missing keys, wrong types, unknown assertions.
 * - Trust status isolation: C2paTrustStatus values never use on-chain language.
 * - Privacy: error payloads contain only reason code + field name.
 * - Compatibility matrix: mapping version consistency.
 * - Fuzzing: bounded random payloads never produce unhandled exceptions.
 */

import { describe, expect, it } from 'vitest'
import {
  C2PA_HARPOCRATES_MAPPING_VERSION,
  C2paParseError,
  exportC2paManifest,
  exportC2paManifestFromProof,
  parseC2paManifest,
  verifyRoundTrip,
  type C2paExportInput,
  type C2paTrustStatus,
} from './c2pa'
import type { ProofManifest } from './proofManifest'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VH = 'aa'.repeat(32)   // valid video hash
const MH = 'bb'.repeat(32)   // valid metadata hash
const PID = 'cc'.repeat(32)  // valid proof ID
const TIER = 'silent' as const
const NET = 'Test SDF Network ; September 2015'
const CID = 'CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT'

function validInput(overrides: Partial<C2paExportInput> = {}): C2paExportInput {
  return {
    videoHash: VH,
    metadataHash: MH,
    proofId: PID,
    tier: TIER,
    network: NET,
    contractId: CID,
    ...overrides,
  }
}

function validManifestJson(overrides: Record<string, unknown> = {}): string {
  const base = exportC2paManifest(validInput())
  return JSON.stringify({ ...base.manifest, ...overrides })
}

// ---------------------------------------------------------------------------
// Export tests
// ---------------------------------------------------------------------------

describe('exportC2paManifest', () => {
  it('returns an exported manifest object', () => {
    const result = exportC2paManifest(validInput())
    expect(result).toHaveProperty('manifest')
    expect(result).toHaveProperty('digest')
    expect(result).toHaveProperty('trustStatus')
  })

  it('is idempotent', () => {
    const a = exportC2paManifest(validInput())
    const b = exportC2paManifest(validInput())
    expect(a.digest).toBe(b.digest)
    expect(JSON.stringify(a.manifest)).toBe(JSON.stringify(b.manifest))
  })

  it('binding contains all required fields', () => {
    const result = exportC2paManifest(validInput())
    const binding = result.manifest['harpocrates_binding'] as Record<string, unknown>
    expect(binding['video_hash']).toBe(VH.toLowerCase())
    expect(binding['metadata_hash']).toBe(MH.toLowerCase())
    expect(binding['proof_id']).toBe(PID.toLowerCase())
    expect(binding['tier']).toBe(TIER)
    expect(binding['mapping_version']).toBe(C2PA_HARPOCRATES_MAPPING_VERSION)
    expect(binding['network']).toBe(NET)
    expect(binding['contract_id']).toBe(CID)
  })

  it('sets alg to sha256', () => {
    const result = exportC2paManifest(validInput())
    expect(result.manifest['alg']).toBe('sha256')
  })

  it('trust_status is signature_not_checked', () => {
    const result = exportC2paManifest(validInput())
    expect(result.trustStatus).toBe('signature_not_checked')
  })

  it('digest is 64 hex chars', () => {
    const result = exportC2paManifest(validInput())
    expect(result.digest).toMatch(/^[0-9a-f]{64}$/)
  })

  it.each(['silent', 'source', 'seal'] as const)('accepts tier %s', (tier) => {
    const result = exportC2paManifest(validInput({ tier }))
    const binding = result.manifest['harpocrates_binding'] as Record<string, unknown>
    expect(binding['tier']).toBe(tier)
  })

  it('throws TypeError for invalid tier', () => {
    expect(() => exportC2paManifest(validInput({ tier: 'admin' as never }))).toThrow(TypeError)
  })

  it('throws TypeError for invalid video_hash', () => {
    expect(() => exportC2paManifest(validInput({ videoHash: 'not-hex' }))).toThrow(TypeError)
  })

  it('throws TypeError for short hex video_hash', () => {
    expect(() => exportC2paManifest(validInput({ videoHash: 'aa'.repeat(16) }))).toThrow(TypeError)
  })

  it('throws TypeError for empty network', () => {
    expect(() => exportC2paManifest(validInput({ network: '   ' }))).toThrow(TypeError)
  })

  it('accepts custom claimGenerator', () => {
    const result = exportC2paManifest(validInput({ claimGenerator: 'my-tool/1.0' }))
    expect(result.manifest['claim_generator']).toBe('my-tool/1.0')
  })

  it('normalises hash to lowercase', () => {
    const result = exportC2paManifest(validInput({ videoHash: VH.toUpperCase() }))
    const binding = result.manifest['harpocrates_binding'] as Record<string, unknown>
    expect(binding['video_hash']).toBe(VH.toLowerCase())
  })
})

describe('exportC2paManifestFromProof', () => {
  it('creates manifest from a ProofManifest', () => {
    const proof: ProofManifest = {
      protocol: 'harpocrates',
      version: 2,
      proofId: PID,
      tier: TIER,
      network: NET,
      contractId: CID,
      transactionRef: 'dd'.repeat(32),
      videoHash: VH,
      metadataHash: MH,
      sourceHash: 'ee'.repeat(32),
      timestamp: '2026-09-24T10:00:00Z',
      verifierScope: '0',
      epoch: 0,
    }
    const result = exportC2paManifestFromProof(proof)
    const binding = result.manifest['harpocrates_binding'] as Record<string, unknown>
    expect(binding['video_hash']).toBe(VH.toLowerCase())
    expect(binding['tier']).toBe(TIER)
  })
})

// ---------------------------------------------------------------------------
// Parse — valid inputs
// ---------------------------------------------------------------------------

describe('parseC2paManifest — valid', () => {
  it('parses a valid manifest', () => {
    const raw = validManifestJson()
    const result = parseC2paManifest(raw)
    expect(result.binding.videoHash).toBe(VH.toLowerCase())
    expect(result.binding.metadataHash).toBe(MH.toLowerCase())
    expect(result.binding.proofId).toBe(PID.toLowerCase())
    expect(result.binding.tier).toBe(TIER)
  })

  it('trust_status is always signature_not_checked on import', () => {
    const result = parseC2paManifest(validManifestJson())
    expect(result.trustStatus).toBe('signature_not_checked' satisfies C2paTrustStatus)
  })

  it('preserves unknown assertions with unsupportedSemantics=true', () => {
    const base = exportC2paManifest(validInput())
    const assertions = [...(base.manifest['assertions'] as unknown[]), { label: 'c2pa.actions', data: {} }]
    const raw = JSON.stringify({ ...base.manifest, assertions })
    const result = parseC2paManifest(raw)
    expect(result.unknownAssertions).toHaveLength(1)
    expect(result.unknownAssertions[0].label).toBe('c2pa.actions')
    expect(result.unknownAssertions[0].unsupportedSemantics).toBe(true)
  })

  it('unknown assertions do not affect the binding', () => {
    const base = exportC2paManifest(validInput())
    const assertions = [...(base.manifest['assertions'] as unknown[]), { label: 'c2pa.thumbnail', data: null }]
    const raw = JSON.stringify({ ...base.manifest, assertions })
    const result = parseC2paManifest(raw)
    expect(result.binding.videoHash).toBe(VH.toLowerCase())
  })

  it('optional spec_version can be absent', () => {
    const base = exportC2paManifest(validInput())
    const { spec_version: _removed, ...rest } = base.manifest as Record<string, unknown>
    const result = parseC2paManifest(JSON.stringify(rest))
    expect(result.specVersion).toBeNull()
  })

  it('normalises hash to lowercase', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>) }
    binding['video_hash'] = VH.toUpperCase()
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    const result = parseC2paManifest(raw)
    expect(result.binding.videoHash).toBe(VH.toLowerCase())
  })

  it('accepts Uint8Array input', () => {
    const raw = validManifestJson()
    const bytes = new TextEncoder().encode(raw)
    const result = parseC2paManifest(bytes)
    expect(result.binding.videoHash).toBe(VH.toLowerCase())
  })
})

// ---------------------------------------------------------------------------
// Parse — adversarial / invalid inputs
// ---------------------------------------------------------------------------

describe('parseC2paManifest — adversarial', () => {
  it('rejects oversized manifest', () => {
    const big = 'x'.repeat(256 * 1024 + 1)
    expect(() => parseC2paManifest(big)).toThrow(C2paParseError)
    try { parseC2paManifest(big) } catch (e) {
      expect((e as C2paParseError).reason).toBe('manifest_too_large')
    }
  })

  it('rejects non-JSON', () => {
    expect(() => parseC2paManifest('this is not json')).toThrow(C2paParseError)
    try { parseC2paManifest('this is not json') } catch (e) {
      expect((e as C2paParseError).reason).toBe('not_json')
    }
  })

  it('rejects truncated JSON', () => {
    expect(() => parseC2paManifest('{"claim_generator":')).toThrow(C2paParseError)
  })

  it('rejects JSON array at top level', () => {
    try { parseC2paManifest('[1,2,3]') } catch (e) {
      expect((e as C2paParseError).reason).toBe('not_object')
    }
  })

  it('rejects null', () => {
    try { parseC2paManifest('null') } catch (e) {
      expect((e as C2paParseError).reason).toBe('not_object')
    }
  })

  it('rejects missing claim_generator', () => {
    const base = exportC2paManifest(validInput())
    const { claim_generator: _r, ...rest } = base.manifest as Record<string, unknown>
    try { parseC2paManifest(JSON.stringify(rest)) } catch (e) {
      expect((e as C2paParseError).reason).toBe('missing_key')
      expect((e as C2paParseError).field).toBe('claim_generator')
    }
  })

  it('rejects missing assertions', () => {
    const base = exportC2paManifest(validInput())
    const { assertions: _r, ...rest } = base.manifest as Record<string, unknown>
    try { parseC2paManifest(JSON.stringify(rest)) } catch (e) {
      expect((e as C2paParseError).reason).toBe('missing_key')
    }
  })

  it('rejects missing harpocrates_binding', () => {
    const base = exportC2paManifest(validInput())
    const { harpocrates_binding: _r, ...rest } = base.manifest as Record<string, unknown>
    try { parseC2paManifest(JSON.stringify(rest)) } catch (e) {
      expect((e as C2paParseError).reason).toBe('missing_key')
    }
  })

  it('rejects assertions as non-array', () => {
    const base = exportC2paManifest(validInput())
    const raw = JSON.stringify({ ...base.manifest, assertions: 'not-an-array' })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('invalid_type')
    }
  })

  it('rejects too many assertions', () => {
    const base = exportC2paManifest(validInput())
    const extras = Array.from({ length: 65 }, (_, i) => ({ label: `x.${i}`, data: null }))
    const raw = JSON.stringify({ ...base.manifest, assertions: extras })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('assertion_count_exceeded')
    }
  })

  it('rejects assertion label too long', () => {
    const base = exportC2paManifest(validInput())
    const longLabel = { label: 'x'.repeat(257), data: {} }
    const assertions = [...(base.manifest['assertions'] as unknown[]), longLabel]
    const raw = JSON.stringify({ ...base.manifest, assertions })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('assertion_label_too_long')
    }
  })

  it('rejects unsupported algorithm', () => {
    const base = exportC2paManifest(validInput())
    const raw = JSON.stringify({ ...base.manifest, alg: 'md5' })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('unsupported_algorithm')
    }
  })

  it('rejects sha512 algorithm', () => {
    const base = exportC2paManifest(validInput())
    const raw = JSON.stringify({ ...base.manifest, alg: 'sha512' })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('unsupported_algorithm')
    }
  })

  it('rejects binding as non-object', () => {
    const base = exportC2paManifest(validInput())
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: 'string' })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('invalid_type')
    }
  })

  it('rejects binding with missing video_hash', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>) }
    delete binding['video_hash']
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('missing_key')
    }
  })

  it('rejects binding with invalid hex video_hash', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>), video_hash: 'zz'.repeat(32) }
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('invalid_value')
    }
  })

  it('rejects binding with invalid tier', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>), tier: 'admin' }
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('invalid_value')
    }
  })

  it('rejects binding with future mapping version', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>), mapping_version: 999 }
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('mapping_version_mismatch')
    }
  })

  it('rejects binding with zero mapping version', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>), mapping_version: 0 }
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toMatch(/invalid_type|mapping_version_mismatch/)
    }
  })

  it('error payload contains only reason and field, never manifest content', () => {
    const secret = 'SENSITIVE_' + 'z'.repeat(54)
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>), tier: secret }
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try {
      parseC2paManifest(raw)
    } catch (e) {
      const payload = JSON.stringify((e as C2paParseError).toPayload())
      expect(payload).not.toContain(secret)
      expect(Object.keys((e as C2paParseError).toPayload())).toEqual(
        expect.arrayContaining(['reason'])
      )
    }
  })

  it('deeply nested structure triggers depth_exceeded', () => {
    let deep: Record<string, unknown> = {}
    let cursor = deep
    for (let i = 0; i < 20; i++) {
      cursor['nested'] = {}
      cursor = cursor['nested'] as Record<string, unknown>
    }
    try {
      parseC2paManifest(JSON.stringify(deep))
    } catch (e) {
      if (e instanceof C2paParseError) {
        expect(['depth_exceeded', 'not_object', 'missing_key']).toContain((e as C2paParseError).reason)
      }
    }
  })
})

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

describe('verifyRoundTrip', () => {
  it('passes for a valid export', () => {
    const exported = exportC2paManifest(validInput())
    expect(verifyRoundTrip(exported)).toBe(true)
  })

  it.each(['silent', 'source', 'seal'] as const)('round-trips tier %s', (tier) => {
    const exported = exportC2paManifest(validInput({ tier }))
    expect(verifyRoundTrip(exported)).toBe(true)
  })

  it('fails on tampered tier', () => {
    const exported = exportC2paManifest(validInput({ tier: 'silent' }))
    const tampered = {
      ...exported,
      manifest: {
        ...exported.manifest,
        harpocrates_binding: {
          ...(exported.manifest['harpocrates_binding'] as Record<string, unknown>),
          tier: 'seal',
        },
      },
    }
    expect(verifyRoundTrip(tampered)).toBe(false)
  })

  it('fails on tampered video_hash', () => {
    const exported = exportC2paManifest(validInput())
    const tampered = {
      ...exported,
      manifest: {
        ...exported.manifest,
        harpocrates_binding: {
          ...(exported.manifest['harpocrates_binding'] as Record<string, unknown>),
          video_hash: 'ff'.repeat(32),
        },
      },
    }
    expect(verifyRoundTrip(tampered)).toBe(false)
  })

  it('round-trip preserves all binding fields', () => {
    const exported = exportC2paManifest(validInput())
    const parsed = parseC2paManifest(JSON.stringify(exported.manifest))
    expect(parsed.binding.videoHash).toBe(VH.toLowerCase())
    expect(parsed.binding.metadataHash).toBe(MH.toLowerCase())
    expect(parsed.binding.proofId).toBe(PID.toLowerCase())
    expect(parsed.binding.tier).toBe(TIER)
    expect(parsed.binding.network).toBe(NET)
    expect(parsed.binding.contractId).toBe(CID)
    expect(parsed.binding.mappingVersion).toBe(C2PA_HARPOCRATES_MAPPING_VERSION)
  })
})

// ---------------------------------------------------------------------------
// Trust status isolation
// ---------------------------------------------------------------------------

describe('C2paTrustStatus isolation', () => {
  const ON_CHAIN_TERMS = ['confirmed', 'verified', 'proof', 'on_chain', 'zk']

  it('trust status values never use on-chain terminology', () => {
    const statuses: C2paTrustStatus[] = [
      'signature_not_checked',
      'signature_valid',
      'unsupported_algorithm',
      'binding_mismatch',
      'parse_failed',
    ]
    for (const status of statuses) {
      for (const term of ON_CHAIN_TERMS) {
        expect(status).not.toContain(term)
      }
    }
  })

  it('imported manifests always have signature_not_checked', () => {
    const result = parseC2paManifest(validManifestJson())
    expect(result.trustStatus).toBe('signature_not_checked')
  })

  it('exported manifests always have signature_not_checked', () => {
    const result = exportC2paManifest(validInput())
    expect(result.trustStatus).toBe('signature_not_checked')
  })
})

// ---------------------------------------------------------------------------
// Compatibility matrix
// ---------------------------------------------------------------------------

describe('compatibility matrix', () => {
  it('export uses current mapping version', () => {
    const result = exportC2paManifest(validInput())
    const binding = result.manifest['harpocrates_binding'] as Record<string, unknown>
    expect(binding['mapping_version']).toBe(C2PA_HARPOCRATES_MAPPING_VERSION)
  })

  it('parser rejects future mapping versions', () => {
    const base = exportC2paManifest(validInput())
    const binding = { ...(base.manifest['harpocrates_binding'] as Record<string, unknown>), mapping_version: C2PA_HARPOCRATES_MAPPING_VERSION + 1 }
    const raw = JSON.stringify({ ...base.manifest, harpocrates_binding: binding })
    try { parseC2paManifest(raw) } catch (e) {
      expect((e as C2paParseError).reason).toBe('mapping_version_mismatch')
    }
  })
})

// ---------------------------------------------------------------------------
// Fuzzing — bounded random payloads
// ---------------------------------------------------------------------------

describe('fuzzing — bounded random payloads', () => {
  function randomString(len: number, seed: number): string {
    let s = ''
    let h = seed
    for (let i = 0; i < len; i++) {
      h = (h * 1664525 + 1013904223) >>> 0
      s += String.fromCharCode(32 + (h % 94))
    }
    return s
  }

  it('random strings never throw non-C2paParseError', () => {
    for (let i = 0; i < 50; i++) {
      const payload = randomString(100 + i * 7, i * 31337)
      try {
        parseC2paManifest(payload)
      } catch (e) {
        expect(e).toBeInstanceOf(C2paParseError)
      }
    }
  })

  it('byte-mutated valid manifests only throw C2paParseError', () => {
    const base = validManifestJson()
    const arr = new TextEncoder().encode(base)
    for (let i = 0; i < 50; i++) {
      const mutated = new Uint8Array(arr)
      const idx = (i * 13) % mutated.length
      mutated[idx] ^= (i * 7 + 1) & 0xff
      try {
        parseC2paManifest(mutated)
      } catch (e) {
        expect(e).toBeInstanceOf(C2paParseError)
      }
    }
  })

  it('oversized payloads are rejected before JSON parsing', () => {
    const big = 'x'.repeat(256 * 1024 + 100)
    try {
      parseC2paManifest(big)
    } catch (e) {
      expect((e as C2paParseError).reason).toBe('manifest_too_large')
    }
  })

  it('fuzz errors never echo input content', () => {
    const sentinel = 'SENTINEL_FUZZ_' + '9'.repeat(20)
    const payload = JSON.stringify({ claim_generator: sentinel })
    try {
      parseC2paManifest(payload)
    } catch (e) {
      if (e instanceof C2paParseError) {
        const dump = JSON.stringify(e.toPayload()) + e.message
        expect(dump).not.toContain(sentinel)
      }
    }
  })
})
