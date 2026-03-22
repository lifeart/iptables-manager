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
 *
 * @example
 *   h('div', { className: 'card' },
 *     h('h2', {}, text('Title')),
 *     h('p', { className: 'body' }, text('Content')),
 *   )
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

/**
 * Create a text node.
 */
export function text(content: string): Text {
  return document.createTextNode(content);
}

/**
 * Add one or more CSS classes to an element.
 */
export function addClass(el: HTMLElement, ...classNames: string[]): void {
  for (const cls of classNames) {
    if (cls) {
      el.classList.add(cls);
    }
  }
}

/**
 * Remove one or more CSS classes from an element.
 */
export function removeClass(el: HTMLElement, ...classNames: string[]): void {
  for (const cls of classNames) {
    if (cls) {
      el.classList.remove(cls);
    }
  }
}

/**
 * Toggle a CSS class on an element.
 */
export function toggleClass(el: HTMLElement, className: string, force?: boolean): void {
  el.classList.toggle(className, force);
}

/**
 * Set text content of an element, only if changed.
 */
export function setText(el: HTMLElement, content: string): void {
  if (el.textContent !== content) {
    el.textContent = content;
  }
}

/**
 * Remove all children from an element.
 */
export function clearChildren(el: HTMLElement): void {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

/**
 * Query a single element within a parent, typed.
 */
export function qs<T extends HTMLElement = HTMLElement>(
  parent: HTMLElement | Document,
  selector: string,
): T | null {
  return parent.querySelector<T>(selector);
}

/**
 * Query all elements within a parent, typed.
 */
export function qsa<T extends HTMLElement = HTMLElement>(
  parent: HTMLElement | Document,
  selector: string,
): T[] {
  return Array.from(parent.querySelectorAll<T>(selector));
}
