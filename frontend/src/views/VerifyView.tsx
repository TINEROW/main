import { useMemo, useRef } from 'react'
import { CheckCircle2, Loader2, RefreshCw, Upload, XCircle } from 'lucide-react'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { ChainProofPanel } from '../components/ChainProofPanel'
import { EventList } from '../components/EventList'
import { ShareVerificationLink } from '../components/ShareVerificationLink'
import VerificationTimeline from '../components/VerificationTimeline'
import { shortHash } from '../utils'
import ProvenanceCard from '../provenance/ProvenanceCard'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import { CONTRACT_NETWORK_PASSPHRASE } from '../stellar'
import type { VerificationShareLinkInput } from '../verificationShareLink'

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

type Props = {
  wallet: string
  networkMismatch?: string | null
  verification: UseVerificationReturn
  provenanceRecord: ProvenanceRecord | null
}

function statusLabel(status: UseVerificationReturn['status']): string {
  switch (status) {
    case 'validating': return 'Validating file…'
    case 'hashing': return 'Hashing evidence…'
    case 'verifying': return 'Inspecting evidence…'
    case 'success': return 'Verification complete.'
    case 'error': return 'Verification did not confirm this artifact.'
    case 'cancelled': return 'Verification cancelled.'
    default: return 'No verification run yet.'
  }
}

export function VerifyView({ wallet, networkMismatch, verification, provenanceRecord }: Props) {
  const {
    verifyHash,
    verifyResult,
    events,
    chainProof,
    status,
    errorCode,
    isVerifying,
    verifyEvidence,
    loadEvents,
    cancel,
    retry,
    clear,
  } = verification

  const inputRef = useRef<HTMLInputElement | null>(null)

  const isError = status === 'error'
  const isCancelled = status === 'cancelled'
  const showRetry = isError && !!errorCode && errorCode !== 'CANCELLED' && errorCode !== 'REVOKED_EVIDENCE' && errorCode !== 'EXPIRED_EVIDENCE'
  // Revoked/expired are terminal trust decisions, retry still allowed but we keep it available via retry button
  const effectiveRetry = isError || isCancelled

  const shareLinkInput = useMemo((): VerificationShareLinkInput | null => {
    if (status !== 'success' || !verifyHash || !CONTRACT_ID) return null
    const matchedEvent = events.find((event) => event.proof_id && event.video_hash === verifyHash)
      ?? events.find((event) => !!event.proof_id)
    const proofId = matchedEvent?.proof_id ?? null
    const metadataHash = chainProof?.metadataHash ?? provenanceRecord?.metadata.metadataHash ?? null
    if (!proofId || !metadataHash) return null
    const tierRaw = matchedEvent?.tier
    const tier =
      tierRaw === 'silent' || tierRaw === 'source' || tierRaw === 'seal' ? tierRaw : undefined
    return {
      videoHash: verifyHash,
      proofId,
      metadataHash,
      network: provenanceRecord?.network.passphrase || CONTRACT_NETWORK_PASSPHRASE,
      contractId: CONTRACT_ID,
      transactionRef: provenanceRecord?.ledger.transactionHash || matchedEvent?.tx_hash || undefined,
      tier,
    }
  }, [status, verifyHash, events, chainProof, provenanceRecord])

  return (
    <section className="workspace app-page verify-page" id="verify">
      <div className="studio verify-studio">
        <header className="page-header">
          <h2 id="verify-heading" tabIndex={-1}>Verify Artifact</h2>
          <p>Inspect a received video against embedded metadata and the Stellar registry.</p>
        </header>

        {networkMismatch ? (
          <div className="network-mismatch-banner" role="alert" aria-live="assertive" aria-atomic="true">
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{networkMismatch}</span>
          </div>
        ) : null}

        <label
          className="dropzone"
          aria-busy={isVerifying}
          // ensure dropzone is a large touch target on mobile
          style={{ minHeight: 140 }}
        >
          {isVerifying ? (
            <Loader2 size={20} className="spin" aria-hidden="true" />
          ) : (
            <Upload size={20} aria-hidden="true" />
          )}
          <span>{isVerifying ? statusLabel(status) : 'Drop or choose a received video'}</span>
          <span className="muted" style={{ fontSize: 11, textAlign: 'center', overflowWrap: 'anywhere' }}>
            MP4, WebM, or MOV · up to 100 MB
          </span>
          <input
            ref={inputRef}
            type="file"
            accept="video/*"
            disabled={isVerifying}
            onChange={(event) => {
              const f = event.target.files?.[0] ?? null
              void verifyEvidence(f, wallet || undefined)
              // allow re-selecting the same file
              event.target.value = ''
            }}
          />
        </label>

        {/* Progress / status live region — always present so mobile screen readers observe changes */}
        <div
          className="verify-progress"
          role="status"
          aria-live="polite"
          aria-atomic="true"
          aria-busy={isVerifying}
        >
          {isVerifying ? (
            <div className="verify-progress-row">
              <Loader2 size={14} className="spin" aria-hidden="true" />
              <span>{statusLabel(status)}</span>
            </div>
          ) : null}
        </div>

        <div
          className={`verify-result large ${isError ? 'verify-error' : ''} ${isCancelled ? 'verify-cancelled' : ''}`}
          role={isError ? 'alert' : 'status'}
          aria-live={isError ? 'assertive' : 'polite'}
          aria-atomic="true"
        >
          {isError ? (
            <XCircle size={14} aria-hidden="true" />
          ) : (
            <CheckCircle2 size={14} aria-hidden="true" />
          )}
          <div style={{ minWidth: 0, flex: 1 }}>
            <p style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
              {verifyResult || statusLabel(status)}
            </p>
            {errorCode ? (
              <p className="muted" style={{ marginTop: 4, fontSize: 11 }}>
                Code: {errorCode}
              </p>
            ) : null}
          </div>
        </div>

        <VerificationTimeline
          status={status}
          verifyHash={verifyHash}
          events={events}
          chainProof={chainProof}
          errorCode={errorCode}
        />

        {/* Action row — reachable on mobile, adequate touch targets */}
        <div className="verify-actions" role="group" aria-label="Verification actions">
          {isVerifying ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={cancel}
              aria-label="Cancel verification"
            >
              Cancel
            </button>
          ) : null}
          {effectiveRetry ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={() => void retry()}
              aria-label="Retry verification"
            >
              <RefreshCw size={14} aria-hidden="true" />
              <span>Retry</span>
            </button>
          ) : null}
          {!isVerifying && (verifyHash || verifyResult) ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={clear}
              aria-label="Clear verification result"
            >
              Clear
            </button>
          ) : null}
          {/* Hidden retry helper for tests / keyboard users */}
          {showRetry ? null : null}
        </div>

        <ShareVerificationLink input={shareLinkInput} />

        <dl className="data-list">
          <div>
            <dt>Received Hash</dt>
            <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>{shortHash(verifyHash)}</dd>
          </div>
          <div>
            <dt>Chain Status</dt>
            <dd>{chainProof ? (chainProof.status === 2 ? 'Revoked' : chainProof.status === 3 ? 'Expired' : 'Confirmed') : 'Not loaded'}</dd>
          </div>
          <div>
            <dt>Wallet</dt>
            <dd>{wallet ? `${wallet.slice(0, 5)}…${wallet.slice(-4)}` : 'Not connected'}</dd>
          </div>
        </dl>
      </div>

      <aside className="side-rail">
        <div className="rail-block">
          <h3>Chain Registry</h3>
          <ChainProofPanel chainProof={chainProof} />
          {provenanceRecord ? <ProvenanceCard provenance={provenanceRecord} /> : null}
        </div>

        <div className="rail-block">
          <h3>Events</h3>
          <EventList events={events} onRefresh={() => void loadEvents()} />
        </div>
      </aside>
    </section>
  )
}
