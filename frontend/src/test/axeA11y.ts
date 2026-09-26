import axe from 'axe-core'

/**
 * Shared axe-core configuration and assertions for the frontend accessibility
 * suite (`src/a11y.axe.test.tsx`).
 *
 * The suite enforces the WCAG 2.2 AA claims documented in ACCESSIBILITY.md
 * against the rendered React tree inside jsdom. jsdom cannot compute real
 * layout geometry, so rules that depend on a browser rendering engine are
 * documented in `MANUAL_ONLY_RULES` and enforced by the manual checklist in
 * ACCESSIBILITY.md instead. Anything else that axe marks as "incomplete" is a
 * fail-closed error so that an acknowledgement can never be added silently.
 */

export const WCAG_AA_TAGS = [
  'wcag2a',
  'wcag2aa',
  'wcag21a',
  'wcag21aa',
  'wcag22aa',
] as const

export const MANUAL_ONLY_RULES: Readonly<Record<string, string>> = {
  'color-contrast':
    'requires real computed layout (jsdom has no rendering engine); enforced manually via the ACCESSIBILITY.md contrast checklist',
}

export type AxeResults = Awaited<ReturnType<typeof axe.run>>

export async function runAxe(root: HTMLElement): Promise<AxeResults> {
  return axe.run(root, {
    runOnly: { type: 'tag', values: [...WCAG_AA_TAGS] },
  })
}

function formatIssues(
  issues: Array<{ id: string; help: string; nodes: Array<{ target: string[] }> }>,
): string {
  if (issues.length === 0) return '  none'
  return issues
    .map(
      (issue) =>
        `  [${issue.id}] ${issue.help}\n    targets: ${issue.nodes
          .map((node) => node.target.join(' '))
          .join(' | ')}`,
    )
    .join('\n')
}

/**
 * Fail-closed assertion:
 *  1. any WCAG-tagged rule violation fails the suite, and
 *  2. any "incomplete" rule that is NOT documented in `MANUAL_ONLY_RULES` also
 *     fails the suite, so a jsdom limitation can never be hidden without an
 *     explicit, reviewed acknowledgement.
 */
export function expectNoA11yViolations(results: AxeResults, context: string): void {
  const unexpectedIncomplete = results.incomplete.filter((r) => !(r.id in MANUAL_ONLY_RULES))
  if (results.violations.length === 0 && unexpectedIncomplete.length === 0) return

  throw new Error(
    `${context}: axe-core reported accessibility issues\n` +
      `violations:\n${formatIssues(results.violations)}\n` +
      `incomplete (not covered by MANUAL_ONLY_RULES):\n${formatIssues(unexpectedIncomplete)}`,
  )
}