/**
 * Group row — stateless render functions for a group in the sidebar.
 */

import type { HostGroup } from '../../store/types';
import { h } from '../../utils/dom';

function createDisclosureSvg(expanded: boolean): SVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', '8');
  svg.setAttribute('height', '8');
  svg.setAttribute('viewBox', '0 0 8 8');
  svg.classList.add('sidebar__disclosure');
  if (expanded) {
    svg.classList.add('sidebar__disclosure--expanded');
  }
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  // Right-pointing triangle; CSS rotation handles expanded state
  path.setAttribute('d', 'M2 1l4 3-4 3z');
  path.setAttribute('fill', 'var(--color-text-secondary)');
  svg.appendChild(path);
  return svg;
}

export function createGroupRow(group: HostGroup, isExpanded: boolean): HTMLElement {
  const row = h('div', {
    className: 'sidebar__group-row',
    tabindex: '0',
    role: 'listitem',
    'aria-expanded': String(isExpanded),
    'aria-label': `${group.name} - ${group.memberHostIds.length} members`,
    dataset: { groupId: group.id, key: group.id },
  });

  const disclosure = createDisclosureSvg(isExpanded);
  row.appendChild(disclosure);

  const nameEl = h('span', { className: 'sidebar__group-name' }, group.name);
  row.appendChild(nameEl);

  const countEl = h('span', { className: 'sidebar__group-count' },
    String(group.memberHostIds.length));
  row.appendChild(countEl);

  // Delete button (visible on hover)
  const deleteBtn = h('button', {
    className: 'sidebar__group-delete-btn',
    type: 'button',
    'aria-label': `Delete group ${group.name}`,
    dataset: { deleteGroupId: group.id },
  }, '\u00D7');
  row.appendChild(deleteBtn);

  return row;
}

export function updateGroupRow(el: HTMLElement, group: HostGroup, isExpanded: boolean): void {
  el.setAttribute('aria-expanded', String(isExpanded));
  el.setAttribute('aria-label', `${group.name} - ${group.memberHostIds.length} members`);
  el.dataset.groupId = group.id;

  // Update disclosure state
  const disclosure = el.querySelector('.sidebar__disclosure');
  if (disclosure) {
    disclosure.classList.toggle('sidebar__disclosure--expanded', isExpanded);
  }

  // Update name
  const nameEl = el.querySelector('.sidebar__group-name');
  if (nameEl && nameEl.textContent !== group.name) {
    nameEl.textContent = group.name;
  }

  // Update count
  const countEl = el.querySelector('.sidebar__group-count');
  const countStr = String(group.memberHostIds.length);
  if (countEl && countEl.textContent !== countStr) {
    countEl.textContent = countStr;
  }
}
