import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import type { VerificationErrorCode, VerificationStatus } from '../hooks/useVerification'

type TimelineState = 'pending' | 'active' | 'complete' | 'failed'

type TimelineStep = {
  id: string
  label: string
  detail: string
  state: TimelineState
}

type Props = {
  status: VerificationStatus
  verifyHash: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  errorCode: VerificationErrorCode | null
}

function markerLabel(state: TimelineState): string {
  if (state === 'complete') return 'Complete'
  if (state === 'active') return 'In progress'
  if (state === 'failed') return 'Not confirmed'
  return 'Pending'
}

export function VerificationTimeline({ status, verifyHash, events, chainProof, errorCode }: Props) {
  const hasRun = status !== 'idle' || Boolean(verifyHash) || events.length > 0 || Boolean(chainProof)
  const isBusy = status === 'validating' || status === 'hashing' || status === 'verifying'
  const failed = status === 'error' || status === 'cancelled'
  const chainFailed = failed && (errorCode === 'REVOKED_EVIDENCE' || errorCode === 'EXPIRED_EVIDENCE')
  const decisionComplete = status === 'success'

  const steps: TimelineStep[] = [
    {
      id: 'input',
      label: 'Evidence received',
      detail: hasRun ? 'Synthetic metadata and local evidence checks are scoped to this run.' : 'Choose an evidence file to begin.',
      state: hasRun ? 'complete' : 'pending',
    },
    {
      id: 'hash',
      label: 'Evidence fingerprinted',
      detail: verifyHash ? 'A local fingerprint is available for the lookup boundary.' : 'The fingerprint is created locally and is never displayed as raw evidence.',
      state: verifyHash ? 'complete' : status === 'hashing' ? 'active' : 'pending',
    },
    {
      id: 'database',
      label: 'Database corroboration',
      detail: events.length > 0 ? `${events.length} matching record${events.length === 1 ? '' : 's'} returned.` : 'No database confirmation has been received.',
      state: events.length > 0 ? 'complete' : status === 'verifying' ? 'active' : failed ? 'failed' : 'pending',
    },
    {
      id: 'chain',
      label: 'Chain record',
      detail: chainProof ? (chainFailed ? 'The chain record is not trusted for this run.' : 'A chain record was returned for this fingerprint.') : 'No chain record has been confirmed.',
      state: chainProof ? (chainFailed ? 'failed' : 'complete') : status === 'verifying' ? 'active' : failed ? 'failed' : 'pending',
    },
    {
      id: 'decision',
      label: 'Verification decision',
      detail: decisionComplete ? 'All available evidence sources corroborated this artifact.' : failed ? 'No trust decision was made.' : 'Waiting for all available evidence sources.',
      state: decisionComplete ? 'complete' : failed ? 'failed' : isBusy ? 'active' : 'pending',
    },
  ]

  return (
    <section className="verification-timeline" aria-labelledby="verification-timeline-heading">
      <div className="verification-timeline__header">
        <div>
          <p className="eyebrow">Evidence path</p>
          <h3 id="verification-timeline-heading">Verification timeline</h3>
        </div>
        <span className="verification-timeline__privacy">No raw evidence</span>
      </div>
      <ol className="verification-timeline__list">
        {steps.map((step) => (
          <li className={`verification-timeline__step verification-timeline__step--${step.state}`} key={step.id}>
            <span className="verification-timeline__marker" aria-hidden="true">
              {step.state === 'complete' ? '✓' : step.state === 'failed' ? '!' : step.state === 'active' ? '•' : '·'}
            </span>
            <div className="verification-timeline__content">
              <div className="verification-timeline__title-row">
                <strong>{step.label}</strong>
                <span>{markerLabel(step.state)}</span>
              </div>
              <p>{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  )
}

export default VerificationTimeline
