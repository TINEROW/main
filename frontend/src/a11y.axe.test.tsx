import React from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import {
  MANUAL_ONLY_RULES,
  expectNoA11yViolations,
  runAxe,
} from './test/axeA11y'

vi.mock('./components/EvilEye', () => ({
  default: () => <div data-testid="evil-eye" />,
}))

const brokenPage = () => {
  const root = document.createElement('div')
  document.body.appendChild(root)
  root.innerHTML = `
      <button><span aria-hidden="true">icon</span></button>
      <a href="/"><span aria-hidden="true">icon</span></a>
      <img src="fixture.png" />
      <input type="text" />
      <div role="img">graphic without alternative text</div>
    `
  return root
}

async function violationsFor(root: HTMLElement) {
  const results = await runAxe(root)
  return results.violations.map((v) => v.id)
}

describe('a11y.axe — WCAG 2.2 AA automated checks', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'scrollTo', {
      configurable: true,
      value: vi.fn(),
    })
    window.history.replaceState(null, '', '/')
  })

  // ── Positive: every rendered view must be axe-clean ─────────────────────────

  it('landing view has no WCAG AA violations', async () => {
    const { container } = render(<App />)
    expectNoA11yViolations(await runAxe(container), 'landing view')
  })

  it('evidence studio (silent tier with secret inputs) has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    expect(screen.getByLabelText(/credential seed/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/nullifier seed/i)).toBeInTheDocument()

    expectNoA11yViolations(await runAxe(container), 'evidence studio (silent tier)')
  })

  it('evidence studio (source tier without secret inputs) has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))
    await user.click(screen.getByRole('button', { name: /consistent source/i }))

    expect(screen.queryByLabelText(/credential seed/i)).not.toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'evidence studio (source tier)')
  })

  it('verify view has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))

    expect(screen.getByLabelText(/drop or choose a received video/i)).toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'verify view')
  })

  it('batch verification workspace has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /batch workspace/i }))

    expectNoA11yViolations(await runAxe(container), 'batch workspace view')
  })

  // ── Negative: the harness must still flag real defects ─────────────────────

  it('flags the negative fixture the same way a browser reporter would', async () => {
    const root = brokenPage()
    try {
      const ids = await violationsFor(root)
      expect(ids).toEqual(
        expect.arrayContaining(['button-name', 'link-name', 'image-alt', 'label', 'role-img-alt']),
      )
    } finally {
      root.remove()
    }
  })

  it('regression: keeps the accessible workflow diagram labelling', async () => {
    const { container } = render(<App />)
    const svg = container.querySelector('svg[role="img"]')
    expect(svg).not.toBeNull()
    expect(svg).toHaveAttribute('aria-labelledby')
    const titleId = svg?.getAttribute('aria-labelledby')
    expect(container.querySelector(`#${titleId}`)).toHaveTextContent(/harpocrates protocol workflow/i)
  })

  // ── Boundary: an empty tree is clean and incomplete rules are disciplined ──

  it('reports no violations for an empty tree', async () => {
    const root = document.createElement('div')
    document.body.appendChild(root)
    try {
      const results = await runAxe(root)
      expect(results.violations).toHaveLength(0)
      expect(results.incomplete).toHaveLength(0)
    } finally {
      root.remove()
    }
  })

  it('accepts only the documented jsdom-limited color-contrast rule as incomplete', async () => {
    const root = document.createElement('div')
    document.body.appendChild(root)
    root.innerHTML = `<p style="color:#333;background:#fff">plain text</p><input type="text" aria-label="named field" />`
    try {
      const results = await runAxe(root)
      expect(results.violations).toHaveLength(0)
      const incompleteIds = results.incomplete.map((r) => r.id)
      expect(incompleteIds).toContain('color-contrast')
      expect(incompleteIds.filter((id) => !(id in MANUAL_ONLY_RULES))).toEqual([])
    } finally {
      root.remove()
    }
  })

  it('fail-closed: rejects an incomplete rule that is not documented as manual-only', () => {
    const fakeResults = {
      violations: [] as never[],
      incomplete: [{ id: 'totally-new-layout-rule', help: '…', nodes: [] } as never],
    } as unknown as Parameters<typeof expectNoA11yViolations>[0]

    expect(() => expectNoA11yViolations(fakeResults, 'test')).toThrow(
      /totally-new-layout-rule/,
    )
  })
})