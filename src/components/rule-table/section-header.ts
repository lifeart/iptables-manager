/**
 * Section header for rule table — titled separator pattern.
 *
 * Example: ── Web Servers ─────────────── 3 rules ── ▾ ──
 */

import { h } from '../../utils/dom';
import { formatCount } from '../../utils/format';

export function createSectionHeader(
  title: string,
  ruleCount: number,
  collapsed: boolean,
): HTMLElement {
  const header = h('div', {
    className: 'rule-table__section-header' + (collapsed ? ' rule-table__section-header--collapsed' : ''),
    role: 'button',
    tabindex: '0',
    'aria-expanded': String(!collapsed),
    'aria-label': `${title} - ${formatCount(ruleCount, 'rule', 'rules')}`,
    dataset: { sectionTitle: title },
  });

  const titleEl = h('span', { className: 'rule-table__section-title' }, title);
  header.appendChild(titleEl);

  const countEl = h('span', { className: 'rule-table__section-count' },
    formatCount(ruleCount, 'rule', 'rules'));
  header.appendChild(countEl);

  const disclosureEl = h('span', {
    className: 'rule-table__section-disclosure',
  }, collapsed ? '\u25B8' : '\u25BE');
  header.appendChild(disclosureEl);

  return header;
}

export function updateSectionHeader(
  el: HTMLElement,
  title: string,
  ruleCount: number,
  collapsed: boolean,
): void {
  el.classList.toggle('rule-table__section-header--collapsed', collapsed);
  el.setAttribute('aria-expanded', String(!collapsed));
  el.setAttribute('aria-label', `${title} - ${formatCount(ruleCount, 'rule', 'rules')}`);

  const titleEl = el.querySelector('.rule-table__section-title');
  if (titleEl && titleEl.textContent !== title) {
    titleEl.textContent = title;
  }

  const countEl = el.querySelector('.rule-table__section-count');
  const countStr = formatCount(ruleCount, 'rule', 'rules');
  if (countEl && countEl.textContent !== countStr) {
    countEl.textContent = countStr;
  }

  const disclosureEl = el.querySelector('.rule-table__section-disclosure');
  const disclosureChar = collapsed ? '\u25B8' : '\u25BE';
  if (disclosureEl && disclosureEl.textContent !== disclosureChar) {
    disclosureEl.textContent = disclosureChar;
  }
}
