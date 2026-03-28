/**
 * Error explanation popover component.
 *
 * Displays a human-readable error explanation with remediation steps
 * when iptables/SSH commands fail. Falls back to raw stderr when no
 * explanation is available.
 */

import { h } from '../../utils/dom';
import type { ErrorExplanation } from '../../bindings';

export interface CommandFailedDetail {
  stderr: string;
  exit_code: number;
  explanation?: ErrorExplanation | null;
}

/**
 * Parse a CommandFailed IpcError detail string into structured data.
 * The detail is JSON-stringified by the IPC bridge when it's an object.
 */
export function parseCommandFailedDetail(
  detail: string,
): CommandFailedDetail | null {
  try {
    const parsed = JSON.parse(detail);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'stderr' in parsed &&
      'exit_code' in parsed
    ) {
      return parsed as CommandFailedDetail;
    }
  } catch {
    // Not valid JSON — not a CommandFailed detail
  }
  return null;
}

/**
 * Show an error explanation popover as a modal overlay.
 * Returns a cleanup function that removes the popover from the DOM.
 */
export function showErrorPopover(detail: CommandFailedDetail): () => void {
  const explanation = detail.explanation;

  // Backdrop
  const backdrop = h('div', { className: 'error-popover__backdrop' });

  // Popover card
  const popover = h('div', {
    className: 'error-popover',
    role: 'dialog',
    'aria-modal': 'true',
  });

  // Header row
  const header = h('div', { className: 'error-popover__header' });
  const headerLeft = h('div', null);

  if (explanation) {
    // Error code badge
    const codeBadge = h(
      'span',
      { className: 'error-popover__code' },
      explanation.code,
    );
    headerLeft.appendChild(codeBadge);

    // Title
    const title = h(
      'h3',
      { className: 'error-popover__title' },
      explanation.title,
    );
    headerLeft.appendChild(title);
  } else {
    // Fallback title when no explanation
    const title = h(
      'h3',
      { className: 'error-popover__title' },
      `Command failed (exit ${detail.exit_code})`,
    );
    headerLeft.appendChild(title);
  }

  // Dismiss button
  const dismissBtn = h(
    'button',
    {
      className: 'error-popover__dismiss',
      type: 'button',
      'aria-label': 'Dismiss',
    },
    '\u00D7',
  );

  header.appendChild(headerLeft);
  header.appendChild(dismissBtn);
  popover.appendChild(header);

  if (explanation) {
    // Explanation paragraph
    const explanationEl = h(
      'p',
      { className: 'error-popover__explanation' },
      explanation.explanation,
    );
    popover.appendChild(explanationEl);

    // Remediation steps
    if (explanation.remediation.length > 0) {
      const remHeader = h(
        'div',
        { className: 'error-popover__remediation-header' },
        'Remediation steps',
      );
      popover.appendChild(remHeader);

      const remList = h('ul', { className: 'error-popover__remediation' });
      for (const step of explanation.remediation) {
        remList.appendChild(h('li', null, step));
      }
      popover.appendChild(remList);
    }
  }

  // Raw stderr (collapsible)
  if (detail.stderr) {
    const stderrSection = h('div', { className: 'error-popover__stderr' });
    const stderrContent = h(
      'pre',
      { className: 'error-popover__stderr-content' },
      detail.stderr,
    );

    if (explanation) {
      // If we have an explanation, stderr is secondary — show as toggle
      stderrContent.style.display = 'none';
      const toggle = h(
        'button',
        { className: 'error-popover__stderr-toggle', type: 'button' },
        'Show raw error output',
      );
      toggle.addEventListener('click', () => {
        const isHidden = stderrContent.style.display === 'none';
        stderrContent.style.display = isHidden ? '' : 'none';
        toggle.textContent = isHidden
          ? 'Hide raw error output'
          : 'Show raw error output';
      });
      stderrSection.appendChild(toggle);
    }

    stderrSection.appendChild(stderrContent);
    popover.appendChild(stderrSection);
  }

  // Footer with copy button
  const footer = h('div', { className: 'error-popover__footer' });
  const copyBtn = h(
    'button',
    { className: 'error-popover__copy-btn', type: 'button' },
    'Copy Error Details',
  );
  copyBtn.addEventListener('click', () => {
    const parts: string[] = [];
    if (explanation) {
      parts.push(`[${explanation.code}] ${explanation.title}`);
      parts.push(explanation.explanation);
      parts.push('');
      parts.push('Remediation:');
      for (const step of explanation.remediation) {
        parts.push(`  - ${step}`);
      }
      parts.push('');
    }
    parts.push(`Exit code: ${detail.exit_code}`);
    if (detail.stderr) {
      parts.push(`Stderr: ${detail.stderr}`);
    }
    const text = parts.join('\n');
    navigator.clipboard
      .writeText(text)
      .then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => {
          copyBtn.textContent = 'Copy Error Details';
        }, 1500);
      })
      .catch(() => {
        copyBtn.textContent = 'Copy failed';
        setTimeout(() => {
          copyBtn.textContent = 'Copy Error Details';
        }, 1500);
      });
  });
  footer.appendChild(copyBtn);
  popover.appendChild(footer);

  backdrop.appendChild(popover);
  document.body.appendChild(backdrop);

  // Dismiss handlers
  const cleanup = () => {
    backdrop.remove();
  };

  dismissBtn.addEventListener('click', cleanup);
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) cleanup();
  });
  const onKeydown = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      cleanup();
      document.removeEventListener('keydown', onKeydown);
    }
  };
  document.addEventListener('keydown', onKeydown);

  return cleanup;
}
