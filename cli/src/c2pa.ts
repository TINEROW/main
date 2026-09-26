import { createHash } from 'node:crypto'
import type { ProofManifest } from './manifest.js'
import { parseManifest, serializeManifest } from './manifest.js'
import type { VerificationReceipt, VerificationResult } from './receipt.js'

/**
 * C2PA authenticity assertion exporter.
 *
 * Produces a Coalition for Content Provenance and Authenticity (C2PA) JSON
 * manifest-definition payload derived exclusively from the canonical
 * Harpocrates proof manifest and (optionally) a verification receipt. The
 * exported assertions reuse the existing canonical metadata, proof, and
 * registry boundaries; they never introduce a second protocol truth.
 *
 * Privacy contract: the exporter emits public manifest and registry fields
 * only. It never receives, embeds, or logs media bytes, witness values,
 * credential secrets, proofs, transaction blobs, or private keys. It does
 * not sign the output – consumers sign the exported assertions with their
 * own C2PA tooling and key material.
 */

export const C2PA_EXPORT_SCHEMA_VERSION = 1
export const C2PA_EXPORTER_NAME = 'Harpocrates C2PA authenticity assertion exporter'
export const C2PA_EXPORTER_VERSION = '1.0.0'
export const CLAIM_GENERATOR = 'harpocrates-cli/c2pa'
export const MAX_C2PA_INPUT_BYTES = 1024 * 1024
export const MAX_C2PA_OUTPUT_BYTES = 256 * 1024

const VERIFICATION_RESULTS: ReadonlySet<string> = new Set([
  'valid', 'expired', 'revoked', 'not_found', 'network_mismatch',
  'contract_mismatch', 'pending', 'failed', 'error',
])
const TRANSACTION_STATUSES: ReadonlySet<string> = new Set([
  'confirmed', 'pending', 'failed', 'missing',
])
const ALLOWED_TIERS: ReadonlySet<string> = new Set(['silent', 'source', 'seal'])

export type C2paAssertion = {
  label: string
  instance?: number
  data: Record<string, unknown>
}

export type C2paExport = {
  format: string
  title?: string
  claim_generator: string
  claim_generator_info: { name: string; version: string }[]
  assertions: C2paAssertion[]
}

export type C2paExportOptions = {
  /** Optional human-readable title carried by the exported claim. */
  title?: string
}

/**
 * Assert that an untrusted C2PA-export input (manifest or receipt) stays
 * within the bounded input limit. Stable, privacy-safe failure message so
 * oversized inputs can never be materialised or echoed downstream.
 */
export function assertC2paInputWithinLimit(serialized: string, label: string): void {
  if (Buffer.byteLength(serialized, 'utf-8') > MAX_C2PA_INPUT_BYTES) {
    throw new Error(`${label} exceeds the 1 MiB input limit`)
  }
}

/**
 * Parse and validate an untrusted verification-receipt JSON value for the
 * C2PA export path. Reuses the canonical manifest parser for the embedded
 * manifest so receipt-boundary inputs fail exactly like top-level manifests.
 */
export function parseC2paReceiptInput(value: unknown): VerificationReceipt {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('receipt must be a JSON object')
  }

  const raw = value as Record<string, unknown>
  if (raw.version !== 1) {
    throw new Error('unsupported receipt version')
  }
  if (typeof raw.verifiedAt !== 'string' || Number.isNaN(Date.parse(raw.verifiedAt))) {
    throw new Error('receipt verification time is invalid')
  }
  if (typeof raw.result !== 'string' || !VERIFICATION_RESULTS.has(raw.result)) {
    throw new Error('receipt result is invalid')
  }

  let manifest: ProofManifest
  try {
    manifest = parseManifest(JSON.stringify(raw.manifest))
  } catch {
    throw new Error('receipt manifest is invalid')
  }

  const transaction = raw.transaction as Record<string, unknown> | undefined
  if (!transaction || typeof transaction !== 'object') {
    throw new Error('receipt transaction is invalid')
  }
  if (typeof transaction.status !== 'string' || !TRANSACTION_STATUSES.has(transaction.status)) {
    throw new Error('receipt transaction status is invalid')
  }
  if (typeof transaction.txHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(transaction.txHash)) {
    throw new Error('receipt transaction hash is invalid')
  }

  const chainRecord = normalizeChainRecord(raw.chainRecord)

  return {
    version: 1,
    verifiedAt: raw.verifiedAt,
    manifest,
    transaction: {
      status: transaction.status as VerificationReceipt['transaction']['status'],
      txHash: transaction.txHash,
      ledger: typeof transaction.ledger === 'number' ? transaction.ledger : undefined,
      contractMatch: typeof transaction.contractMatch === 'boolean'
        ? transaction.contractMatch
        : undefined,
    },
    chainRecord,
    result: raw.result as VerificationResult,
  }
}

function normalizeChainRecord(value: unknown): VerificationReceipt['chainRecord'] {
  if (value === null || value === undefined) return null
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('receipt chainRecord is invalid')
  }
  const raw = value as Record<string, unknown>
  if (typeof raw.status !== 'number' || !Number.isInteger(raw.status)) {
    throw new Error('receipt chainRecord status is invalid')
  }
  if (typeof raw.createdAt !== 'string') {
    throw new Error('receipt chainRecord createdAt is invalid')
  }
  return {
    videoHash: '',
    metadataHash: '',
    tier: typeof raw.tier === 'number' ? raw.tier : 0,
    status: raw.status,
    createdAt: raw.createdAt,
    expiresAt: typeof raw.expiresAt === 'string' ? raw.expiresAt : undefined,
    source: typeof raw.source === 'string' ? raw.source : null,
    issuer: typeof raw.issuer === 'string' ? raw.issuer : null,
  }
}

/**
 * Assert that a candidate manifest is supported for C2PA export. Reuses the
 * canonical manifest validator; unsupported versions and unknown fields are
 * rejected with a stable message instead of being silently exported.
 */
export function assertSupportedManifest(manifest: ProofManifest): void {
  if (manifest.protocol !== 'harpocrates') {
    throw new Error('manifest protocol must be "harpocrates"')
  }
  if (manifest.version !== 1 && manifest.version !== 2) {
    throw new Error('unsupported manifest version')
  }
  if (!ALLOWED_TIERS.has(manifest.tier)) {
    throw new Error(`manifest tier must be one of: ${[...ALLOWED_TIERS].join(', ')}`)
  }
  for (const field of ['proofId', 'metadataHash', 'sourceHash', 'videoHash', 'transactionRef']) {
    if (!/^[0-9a-fA-F]{64}$/.test(manifest[field as keyof ProofManifest] as string)) {
      throw new Error(`manifest.${field} must be a 32-byte hex string`)
    }
  }
  if (Number.isNaN(Date.parse(manifest.timestamp))) {
    throw new Error('manifest.timestamp must be a valid date')
  }
}

/**
 * Build C2PA authenticity assertions from a canonical proof manifest and an
 * optional matching verification receipt.
 *
 * The output is deterministic for identical inputs (no injected clocks, no
 * random identifiers) so the same evidence always exports the same bytes.
 * Expired, revoked, pending, or failed verification results are recorded
 * verbatim in the exported `harpocrates.verification.v1` assertion; a false
 * "valid" status is never fabricated.
 */
export function exportC2paAssertions(
  manifest: ProofManifest,
  receipt?: VerificationReceipt,
  options: C2paExportOptions = {},
): C2paExport {
  assertSupportedManifest(manifest)
  const manifestHash = canonicalHashJson(serializeManifest(manifest))

  if (receipt) {
    assertReceiptMatchesManifest(receipt, manifest)
  }

  const assertions: C2paAssertion[] = [
    actionAssertion(manifest),
    contentHashAssertion(manifest),
    registryAssertion(manifest, manifestHash),
  ]
  if (receipt) {
    assertions.push(verificationAssertion(receipt))
  }
  assertions.push(exportAssertion(manifest, manifestHash, receipt))

  const exported: C2paExport = {
    format: 'application/json',
    claim_generator: CLAIM_GENERATOR,
    claim_generator_info: [
      { name: C2PA_EXPORTER_NAME, version: C2PA_EXPORTER_VERSION },
    ],
    assertions,
  }
  if (options.title) {
    exported.title = options.title
  }

  if (Buffer.byteLength(serializeC2paExport(exported), 'utf-8') > MAX_C2PA_OUTPUT_BYTES) {
    throw new Error('c2pa export exceeds the 256 KiB output limit')
  }
  return exported
}

function actionAssertion(manifest: ProofManifest): C2paAssertion {
  return {
    label: 'c2pa.actions.v2',
    data: {
      actions: [
        {
          action: 'harpocrates.registered',
          when: manifest.timestamp,
          softwareAgent: { name: 'Harpocrates Protocol' },
          parameters: {
            tier: manifest.tier,
            network: manifest.network,
            contractId: manifest.contractId,
            transactionRef: manifest.transactionRef,
            proofId: manifest.proofId,
          },
        },
      ],
      allActionsIncluded: true,
    },
  }
}

function contentHashAssertion(manifest: ProofManifest): C2paAssertion {
  return {
    label: 'c2pa.hash.data',
    data: {
      alg: 'sha256',
      name: 'video',
      hash: base64Encode(hexToBytes(manifest.videoHash)),
      pad: ' ',
    },
  }
}

function registryAssertion(manifest: ProofManifest, manifestHash: string): C2paAssertion {
  const data: Record<string, unknown> = {
    schemaVersion: 1,
    protocol: manifest.protocol,
    manifestVersion: manifest.version,
    manifestHash,
    proofId: manifest.proofId,
    metadataHash: manifest.metadataHash,
    sourceHash: manifest.sourceHash,
    videoHash: manifest.videoHash,
    tier: manifest.tier,
    network: manifest.network,
    contractId: manifest.contractId,
    transactionRef: manifest.transactionRef,
    timestamp: manifest.timestamp,
  }
  if (manifest.verifierScope !== undefined) data.verifierScope = manifest.verifierScope
  if (manifest.epoch !== undefined) data.epoch = manifest.epoch
  if (manifest.scopeName !== undefined) data.scopeName = manifest.scopeName
  if (manifest.selectiveDisclosure?.schemaHash !== undefined) {
    data.selectiveDisclosureSchemaHash = manifest.selectiveDisclosure.schemaHash
  }
  if (manifest.selectiveDisclosure?.circuitVersion !== undefined) {
    data.selectiveDisclosureCircuitVersion = manifest.selectiveDisclosure.circuitVersion
  }
  return { label: 'harpocrates.registry.v1', data }
}

function verificationAssertion(receipt: VerificationReceipt): C2paAssertion {
  const data: Record<string, unknown> = {
    schemaVersion: 1,
    result: receipt.result,
    verifiedAt: receipt.verifiedAt,
    transaction: {
      status: receipt.transaction.status,
      txHash: receipt.transaction.txHash,
    },
  }
  if (receipt.chainRecord) {
    data.chainRecord = {
      status: receipt.chainRecord.status,
      createdAt: receipt.chainRecord.createdAt,
      expiresAt: receipt.chainRecord.expiresAt ?? null,
    }
  }
  return { label: 'harpocrates.verification.v1', data }
}

function exportAssertion(
  manifest: ProofManifest,
  manifestHash: string,
  receipt: VerificationReceipt | undefined,
): C2paAssertion {
  return {
    label: 'harpocrates.export.v1',
    data: {
      schemaVersion: C2PA_EXPORT_SCHEMA_VERSION,
      unsigned: true,
      exporter: { name: C2PA_EXPORTER_NAME, version: C2PA_EXPORTER_VERSION },
      input: {
        manifestVersion: manifest.version,
        manifestHash,
        receiptVersion: receipt?.version ?? null,
      },
      privacy:
        'public manifest and registry fields only; no media, secrets, witnesses, or keys',
    },
  }
}

function assertReceiptMatchesManifest(receipt: VerificationReceipt, manifest: ProofManifest): void {
  if (receipt.manifest.proofId.toLowerCase() !== manifest.proofId.toLowerCase() ||
      receipt.manifest.metadataHash.toLowerCase() !== manifest.metadataHash.toLowerCase() ||
      receipt.manifest.videoHash.toLowerCase() !== manifest.videoHash.toLowerCase()) {
    throw new Error('receipt does not match the supplied manifest')
  }
}

/**
 * Serialise the export deterministically: object keys are sorted, arrays keep
 * their order, and no whitespace is emitted. Identical inputs always produce
 * identical bytes.
 */
export function serializeC2paExport(value: unknown): string {
  return canonicalJson(value)
}

/**
 * Canonical SHA-256 of the serialised export, useful for fixture pinning and
 * drift detection.
 */
export function c2paExportDigest(exported: C2paExport): string {
  return createHash('sha256').update(serializeC2paExport(exported)).digest('hex')
}

function canonicalHashJson(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`
}

function base64Encode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}