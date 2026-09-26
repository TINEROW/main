import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { parseManifest, serializeManifest, createProofManifest, type ProofManifest } from '../src/manifest.js'
import { createReceipt, type VerificationReceipt } from '../src/receipt.js'
import {
  exportC2paAssertions,
  parseC2paReceiptInput,
  serializeC2paExport,
  c2paExportDigest,
  assertC2paInputWithinLimit,
  MAX_C2PA_INPUT_BYTES,
  C2PA_EXPORTER_NAME,
  C2PA_EXPORTER_VERSION,
} from '../src/c2pa.js'

const H64 = (seed: string): string => seed.repeat(Math.ceil(64 / seed.length)).slice(0, 64)

const VALID_INPUT = {
  proofId: H64('a0b1c2d3e4f5'),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  transactionRef: H64('c2d3e4f5a6b7'),
  videoHash: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
  metadataHash: 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef',
  sourceHash: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
  timestamp: '2026-07-24T12:00:00.000Z',
  verifierScope: '0',
  epoch: 0,
  scopeName: 'evidence-verification-portal',
}

function validManifest(): ProofManifest {
  return createProofManifest(VALID_INPUT)
}

function validReceipt(result: VerificationReceipt['result'] = 'valid'): VerificationReceipt {
  const manifest = validManifest()
  return createReceipt(
    manifest,
    {
      status: 'confirmed',
      txHash: manifest.transactionRef,
      ledger: 123456,
      contractMatch: true,
    },
    {
      videoHash: manifest.videoHash,
      metadataHash: manifest.metadataHash,
      tier: 1,
      status: 1,
      createdAt: '123456',
      expiresAt: '999999',
      source: null,
      issuer: null,
    },
    result,
  )
}

describe('exportC2paAssertions', () => {
  it('emits the standard and namespaced authenticity assertions', () => {
    const manifest = validManifest()
    const exported = exportC2paAssertions(manifest, validReceipt())
    const labels = exported.assertions.map((a) => a.label)
    expect(labels).toEqual([
      'c2pa.actions.v2',
      'c2pa.hash.data',
      'harpocrates.registry.v1',
      'harpocrates.verification.v1',
      'harpocrates.export.v1',
    ])
    expect(exported.claim_generator).toBe('harpocrates-cli/c2pa')
    expect(exported.format).toBe('application/json')
    expect(exported.claim_generator_info).toEqual([
      { name: C2PA_EXPORTER_NAME, version: C2PA_EXPORTER_VERSION },
    ])
  })

  it('omits the verification assertion when no receipt is supplied', () => {
    const exported = exportC2paAssertions(validManifest())
    const labels = exported.assertions.map((a) => a.label)
    expect(labels).not.toContain('harpocrates.verification.v1')
    expect(labels).toContain('harpocrates.export.v1')
  })

  it('binds the canonical manifest via manifestHash', () => {
    const manifest = validManifest()
    const registry = exportC2paAssertions(manifest).assertions
      .find((a) => a.label === 'harpocrates.registry.v1')!
    const data = registry.data as { manifestHash: string }
    const expected = createHash('sha256').update(serializeManifest(manifest)).digest('hex')
    expect(data.manifestHash).toBe(expected)
  })

  it('carries the registered content hash binding', () => {
    const manifest = validManifest()
    const hashAssertion = exportC2paAssertions(manifest).assertions
      .find((a) => a.label === 'c2pa.hash.data')!
    const data = hashAssertion.data as { alg: string; hash: string; name: string }
    expect(data.alg).toBe('sha256')
    expect(data.name).toBe('video')
    const bytes = Buffer.from(manifest.videoHash, 'hex')
    expect(data.hash).toBe(bytes.toString('base64'))
  })

  it('records the action parameters from the canonical manifest', () => {
    const manifest = validManifest()
    const actions = exportC2paAssertions(manifest).assertions
      .find((a) => a.label === 'c2pa.actions.v2')!
    expect(actions.data).toMatchObject({
      allActionsIncluded: true,
      actions: [
        {
          action: 'harpocrates.registered',
          when: manifest.timestamp,
          parameters: {
            tier: manifest.tier,
            network: manifest.network,
            contractId: manifest.contractId,
            transactionRef: manifest.transactionRef,
            proofId: manifest.proofId,
          },
        },
      ],
    })
  })

  it('applies an optional title', () => {
    const exported = exportC2paAssertions(validManifest(), undefined, { title: 'synthetic' })
    expect(exported.title).toBe('synthetic')
  })

  it('is deterministic across invocations', () => {
    const receipt = validReceipt()
    const manifest = validManifest()
    const first = serializeC2paExport(exportC2paAssertions(manifest, receipt))
    const second = serializeC2paExport(exportC2paAssertions(manifest, receipt))
    expect(first).toBe(second)
    expect(c2paExportDigest(exportC2paAssertions(manifest))).toBe(
      c2paExportDigest(exportC2paAssertions(manifest)),
    )
  })
})

describe('verification outcome boundary', () => {
  it.each(['valid', 'expired', 'revoked', 'not_found', 'pending', 'failed', 'network_mismatch', 'contract_mismatch', 'error'] as const)(
    'records %s verbatim without fabricating validity',
    (result) => {
      const exported = exportC2paAssertions(validManifest(), validReceipt(result))
      const verification = exported.assertions
        .find((a) => a.label === 'harpocrates.verification.v1')!
      expect((verification.data as { result: string }).result).toBe(result)
    },
  )

  it('does not fabricate a valid status for revoked evidence', () => {
    const exported = exportC2paAssertions(validManifest(), validReceipt('revoked'))
    const blob = serializeC2paExport(exported)
    const verification = exported.assertions
      .find((a) => a.label === 'harpocrates.verification.v1')!
    expect((verification.data as { result: string }).result).toBe('revoked')
    expect(blob).not.toContain('"result":"valid"')
  })

  it('rejects a receipt belonging to a different proof', () => {
    const manifest = validManifest()
    const other = createReceipt(
      { ...manifest, proofId: 'ff'.repeat(32) },
      { status: 'confirmed', txHash: manifest.transactionRef },
      null,
      'valid',
    )
    expect(() => exportC2paAssertions(manifest, other)).toThrow(
      'receipt does not match the supplied manifest',
    )
  })
})

describe('malformed and unsupported inputs', () => {
  it('rejects an unsupported manifest version', () => {
    const manifest = { ...validManifest(), version: 3 }
    expect(() => exportC2paAssertions(manifest)).toThrow('unsupported manifest version')
  })

  it('rejects metadata that the canonical manifest validator rejects', () => {
    const raw = {
      ...VALID_INPUT,
      credentialSecret: 'should-never-be-exported',
    }
    const payload = JSON.stringify({ ...raw, protocol: 'harpocrates', version: 2 })
    expect(() => parseManifest(payload)).toThrow('manifest contains unsupported fields')
  })

  it('rejects an unsupported receipt version through the canonical receipt parser', () => {
    const receipt = { ...validReceipt(), version: 2 }
    expect(() => parseC2paReceiptInput(receipt)).toThrow('unsupported receipt version')
  })

  it('rejects a receipt with an invalid result', () => {
    const receipt = { ...validReceipt(), result: 'celebrated' }
    expect(() => parseC2paReceiptInput(receipt)).toThrow('receipt result is invalid')
  })

  it('rejects a receipt with an invalid embedded manifest', () => {
    const receipt = validReceipt()
    const broken = {
      ...receipt,
      manifest: { ...receipt.manifest, protocol: 'not-harpocrates' },
    }
    expect(() => parseC2paReceiptInput(broken)).toThrow('receipt manifest is invalid')
  })

  it('rejects oversized C2PA inputs with a stable message', () => {
    expect(() => assertC2paInputWithinLimit('x'.repeat(MAX_C2PA_INPUT_BYTES + 1), 'manifest')).toThrow(
      'manifest exceeds the 1 MiB input limit',
    )
    expect(() => assertC2paInputWithinLimit('ok', 'receipt')).not.toThrow()
  })

  it('rejects exports that exceed the output limit', () => {
    const manifest = validManifest()
    expect(() =>
      exportC2paAssertions(manifest, undefined, { title: 'x'.repeat(300 * 1024) }),
    ).toThrow('c2pa export exceeds the 256 KiB output limit')
  })
})

describe('privacy regression', () => {
  it('never serialises secrets, witnesses, private keys, or signer material', () => {
    const exported = exportC2paAssertions(validManifest(), validReceipt())
    const blob = serializeC2paExport(exported).toLowerCase()
    for (const token of [
      'credentialsecret',
      'nullifiersecret',
      'privatekey',
      'sign_cert',
      'signcert',
      'begin rsa private key',
      'should-never-be-exported',
      'seed',
      'witness_value',
      'proofbytes',
    ]) {
      expect(blob).not.toContain(token)
    }
    for (const assertion of exported.assertions) {
      expect(Object.keys(assertion.data)).not.toContain('privateKey')
      expect(Object.keys(assertion.data)).not.toContain('signCert')
    }
  })

  it('declares the export unsigned', () => {
    const exported = exportC2paAssertions(validManifest(), validReceipt())
    const exportAssertion = exported.assertions.find((a) => a.label === 'harpocrates.export.v1')!
    expect((exportAssertion.data as { unsigned: boolean }).unsigned).toBe(true)
  })
})

describe('committed interop fixture regression', () => {
  function fixturePath(name: string): string {
    return new URL(`../../devx/fixtures/c2pa/${name}`, import.meta.url).pathname
  }

  it('still matches the committed expected export byte-for-byte', () => {
    const manifest = parseManifest(readFileSync(fixturePath('manifest.json'), 'utf-8'))
    const receipt = parseC2paReceiptInput(JSON.parse(readFileSync(fixturePath('receipt.json'), 'utf-8')))
    const expected = readFileSync(fixturePath('expected-export.json'), 'utf-8').trim()
    const rendered = serializeC2paExport(exportC2paAssertions(manifest, receipt))
    expect(rendered).toBe(expected)
  })
})