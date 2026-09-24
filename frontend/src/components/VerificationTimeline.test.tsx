import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import VerificationTimeline from './VerificationTimeline'

const baseProps = {
  verifyHash: '',
  events: [],
  chainProof: null,
  errorCode: null,
} as const

describe('VerificationTimeline', () => {
  it('shows the initial pending path without exposing evidence values', () => {
    render(<VerificationTimeline {...baseProps} status="idle" />)

    expect(screen.getByRole('heading', { name: 'Verification timeline' })).toBeInTheDocument()
    expect(screen.getAllByText('Pending')).toHaveLength(5)
    expect(screen.getByText('No raw evidence')).toBeInTheDocument()
  })

  it('shows completed corroboration stages for a successful verification', () => {
    render(
      <VerificationTimeline
        status="success"
        verifyHash={'a'.repeat(64)}
        events={[{
          id: 1,
          event_type: 'registered',
          file_name: null,
          video_hash: null,
          proof_id: null,
          tier: 'silent',
          created_at: '2026-01-01T00:00:00Z',
        }]}
        chainProof={{
          videoHash: 'b'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 1,
          createdAt: '2026-01-01T00:00:00Z',
          source: null,
          issuer: null,
        }}
        errorCode={null}
      />,
    )

    expect(screen.getAllByText('Complete')).toHaveLength(5)
    expect(screen.getByText('1 matching record returned.')).toBeInTheDocument()
  })

  it('renders stable failure states for revoked evidence', () => {
    render(
      <VerificationTimeline
        status="error"
        {...baseProps}
        chainProof={{
          videoHash: 'b'.repeat(64),
          metadataHash: 'c'.repeat(64),
          tier: 1,
          status: 2,
          createdAt: '2026-01-01T00:00:00Z',
          source: null,
          issuer: null,
        }}
        errorCode="REVOKED_EVIDENCE"
      />,
    )

    expect(screen.getAllByText('Not confirmed').length).toBeGreaterThan(0)
    expect(screen.getByText('The chain record is not trusted for this run.')).toBeInTheDocument()
    expect(screen.getByText('No trust decision was made.')).toBeInTheDocument()
  })
})
