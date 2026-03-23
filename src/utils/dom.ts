/**
 * DOM helper utilities.
 */

type ElementAttributes = {
  className?: string;
  id?: string;
  dataset?: Record<string, string>;
  style?: Partial<CSSStyleDeclaration>;
  [key: string]: unknown;
};

/**
 * Create an HTML element with attributes and children.
 */
export function h(
  tag: string,
  attrs?: ElementAttributes | null,
  ...children: (Node | string)[]
): HTMLElement {
  const el = document.createElement(tag);

  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null) continue;

      if (key === 'className') {
        el.className = value as string;
      } else if (key === 'dataset') {
        const data = value as Record<string, string>;
        for (const [dk, dv] of Object.entries(data)) {
          el.dataset[dk] = dv;
        }
      } else if (key === 'style') {
        const styles = value as Partial<CSSStyleDeclaration>;
        for (const [sk, sv] of Object.entries(styles)) {
          (el.style as unknown as Record<string, unknown>)[sk] = sv;
        }
      } else if (key.startsWith('on') && typeof value === 'function') {
        const eventName = key.slice(2).toLowerCase();
        el.addEventListener(eventName, value as EventListener);
      } else if (value === true) {
        el.setAttribute(key, '');
      } else if (value === false) {
        el.removeAttribute(key);
      } else {
        el.setAttribute(key, String(value));
      }
    }
  }

  for (const child of children) {
    if (typeof child === 'string') {
      el.appendChild(document.createTextNode(child));
    } else {
      el.appendChild(child);
    }
  }

  return el;
}

/** Remove all children from an element. */
export function clearChildren(el: HTMLElement): void {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Trap focus within a dialog element.
 * Intercepts Tab/Shift+Tab and wraps focus among focusable elements.
 */
export function trapFocus(dialogEl: HTMLElement, signal?: AbortSignal): void {
  const handler = (e: KeyboardEvent) => {
    if (e.key !== 'Tab') return;

    const focusable = Array.from(
      dialogEl.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
    ).filter(el => el.offsetParent !== null);

    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  dialogEl.addEventListener('keydown', handler as EventListener, { signal });
}
