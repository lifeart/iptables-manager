/**
 * Host row — stateless render functions for a single host in the sidebar.
 *
 * Status indicators use distinct SVG shapes for accessibility.
 */

import type { Host, HostStatus, MixedBackendInfo, PersistenceStatus } from '../../store/types';
import { h } from '../../utils/dom';

// ─── Status SVG Generators ──────────────────────────────────

const STATUS_CONFIGS: Record<HostStatus, { color: string; label: string }> = {
  connected:    { color: 'var(--color-allow)',    label: 'Connected' },
  drifted:      { color: 'var(--color-warning)',  label: 'Drifted' },
  disconnected: { color: 'var(--color-block)',    label: 'Disconnected' },
  unreachable:  { color: 'var(--color-disabled)', label: 'Unreachable' },
  connecting:   { color: 'var(--color-info)',     label: 'Connecting' },
  pending:      { color: 'var(--color-info)',     label: 'Pending changes' },
};

function createStatusSvg(status: HostStatus): SVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', '8');
  svg.setAttribute('height', '8');
  svg.setAttribute('viewBox', '0 0 8 8');
  svg.classList.add('sidebar__status-icon');
  svg.setAttribute('aria-label', STATUS_CONFIGS[status].label);

  const color = STATUS_CONFIGS[status].color;

  switch (status) {
    case 'connected': {
      // Filled circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '4');
      circle.setAttribute('cy', '4');
      circle.setAttribute('r', '3.5');
      circle.setAttribute('fill', color);
      svg.appendChild(circle);
      break;
    }
    case 'drifted': {
      // Filled equilateral triangle
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
      path.setAttribute('points', '4,0.5 7.5,7 0.5,7');
      path.setAttribute('fill', color);
      svg.appendChild(path);
      break;
    }
    case 'disconnected': {
      // Circle with X stroke
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '4');
      circle.setAttribute('cy', '4');
      circle.setAttribute('r', '3');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', color);
      circle.setAttribute('stroke-width', '1.5');
      svg.appendChild(circle);
      const line1 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line1.setAttribute('x1', '2.5');
      line1.setAttribute('y1', '2.5');
      line1.setAttribute('x2', '5.5');
      line1.setAttribute('y2', '5.5');
      line1.setAttribute('stroke', color);
      line1.setAttribute('stroke-width', '1.2');
      svg.appendChild(line1);
      const line2 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line2.setAttribute('x1', '5.5');
      line2.setAttribute('y1', '2.5');
      line2.setAttribute('x2', '2.5');
      line2.setAttribute('y2', '5.5');
      line2.setAttribute('stroke', color);
      line2.setAttribute('stroke-width', '1.2');
      svg.appendChild(line2);
      break;
    }
    case 'unreachable': {
      // Hollow circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '4');
      circle.setAttribute('cy', '4');
      circle.setAttribute('r', '3');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', color);
      circle.setAttribute('stroke-width', '1.5');
      svg.appendChild(circle);
      break;
    }
    case 'connecting': {
      // Animated ring — circle with 90-degree arc rotating
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '4');
      circle.setAttribute('cy', '4');
      circle.setAttribute('r', '3');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', color);
      circle.setAttribute('stroke-width', '1.5');
      circle.setAttribute('stroke-dasharray', '4.71 14.14');
      circle.setAttribute('stroke-linecap', 'round');
      svg.appendChild(circle);
      svg.classList.add('sidebar__status-icon--spinning');
      break;
    }
    case 'pending': {
      // Circle with concentric dot
      const outerCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      outerCircle.setAttribute('cx', '4');
      outerCircle.setAttribute('cy', '4');
      outerCircle.setAttribute('r', '3');
      outerCircle.setAttribute('fill', 'none');
      outerCircle.setAttribute('stroke', color);
      outerCircle.setAttribute('stroke-width', '1.5');
      svg.appendChild(outerCircle);
      const innerDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      innerDot.setAttribute('cx', '4');
      innerDot.setAttribute('cy', '4');
      innerDot.setAttribute('r', '1.5');
      innerDot.setAttribute('fill', color);
      svg.appendChild(innerDot);
      break;
    }
  }

  return svg;
}

function createChevronSvg(): SVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', '6');
  svg.setAttribute('height', '10');
  svg.setAttribute('viewBox', '0 0 6 10');
  svg.classList.add('sidebar__chevron');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M1 1l4 4-4 4');
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'var(--color-disabled)');
  path.setAttribute('stroke-width', '1.5');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  svg.appendChild(path);
  return svg;
}

// ─── Persistence Badge Helper ────────────────────────────────

function needsPersistenceBadge(ps?: PersistenceStatus): boolean {
  if (!ps) return false;
  return !ps.packageInstalled || !ps.serviceEnabled;
}

// ─── Host Row Create/Update ──────────────────────────────────

export function createHostRow(host: Host, isActive: boolean, mixedBackendAlerts?: Map<string, MixedBackendInfo>): HTMLElement {
  const row = h('div', {
    className: 'sidebar__host-row' + (isActive ? ' sidebar__host-row--selected' : ''),
    tabindex: '0',
    role: 'listitem',
    'aria-label': `${host.name} - ${STATUS_CONFIGS[host.status].label}`,
    dataset: { hostId: host.id, key: host.id },
  });

  const indicator = createStatusSvg(host.status);
  row.appendChild(indicator);
  row.dataset.status = host.status;

  const nameEl = h('span', { className: 'sidebar__host-name' }, host.name);
  row.appendChild(nameEl);

  // Mixed backend warning icon
  if (mixedBackendAlerts && mixedBackendAlerts.has(host.id)) {
    const warnIcon = h('span', {
      className: 'sidebar__mixed-backend-warn',
      title: 'Mixed iptables backend detected',
      'aria-label': 'Mixed iptables backend warning',
    }, '\u26A0');
    row.appendChild(warnIcon);
  }

  // Persistence badge
  if (needsPersistenceBadge(host.capabilities?.persistenceStatus)) {
    const badge = h('span', {
      className: 'sidebar__persistence-badge',
      title: 'Rules not persistent \u2014 will be lost on reboot',
    }, 'NP');
    row.appendChild(badge);
  }

  const chevron = createChevronSvg();
  row.appendChild(chevron);

  // Delete button (visible on hover)
  const deleteBtn = h('button', {
    className: 'sidebar__host-delete-btn',
    type: 'button',
    'aria-label': `Delete ${host.name}`,
    dataset: { deleteHostId: host.id },
  }, '\u00D7');
  row.appendChild(deleteBtn);

  return row;
}

export function updateHostRow(el: HTMLElement, host: Host, isActive: boolean, mixedBackendAlerts?: Map<string, MixedBackendInfo>): void {
  // Update selected state
  el.classList.toggle('sidebar__host-row--selected', isActive);
  el.setAttribute('aria-label', `${host.name} - ${STATUS_CONFIGS[host.status].label}`);
  el.dataset.hostId = host.id;

  // Update status indicator only when status actually changes
  if (el.dataset.status !== host.status) {
    el.dataset.status = host.status;
    const existingIcon = el.querySelector('.sidebar__status-icon');
    if (existingIcon) {
      const newIcon = createStatusSvg(host.status);
      existingIcon.replaceWith(newIcon);
    }
  }

  // Update hostname
  const nameEl = el.querySelector('.sidebar__host-name');
  if (nameEl && nameEl.textContent !== host.name) {
    nameEl.textContent = host.name;
  }

  // Update mixed backend warning icon
  const existingWarn = el.querySelector('.sidebar__mixed-backend-warn');
  const hasMixed = mixedBackendAlerts && mixedBackendAlerts.has(host.id);
  if (hasMixed && !existingWarn) {
    const warnIcon = h('span', {
      className: 'sidebar__mixed-backend-warn',
      title: 'Mixed iptables backend detected',
      'aria-label': 'Mixed iptables backend warning',
    }, '\u26A0');
    // Insert before chevron
    const chevron = el.querySelector('.sidebar__chevron');
    if (chevron) {
      el.insertBefore(warnIcon, chevron);
    } else {
      el.appendChild(warnIcon);
    }
  } else if (!hasMixed && existingWarn) {
    existingWarn.remove();
  }

  // Update persistence badge
  const existingBadge = el.querySelector('.sidebar__persistence-badge');
  const showBadge = needsPersistenceBadge(host.capabilities?.persistenceStatus);
  if (showBadge && !existingBadge) {
    const badge = h('span', {
      className: 'sidebar__persistence-badge',
      title: 'Rules not persistent \u2014 will be lost on reboot',
    }, 'NP');
    // Insert before chevron
    const chevron2 = el.querySelector('.sidebar__chevron');
    if (chevron2) {
      el.insertBefore(badge, chevron2);
    } else {
      el.appendChild(badge);
    }
  } else if (!showBadge && existingBadge) {
    existingBadge.remove();
  }
}
