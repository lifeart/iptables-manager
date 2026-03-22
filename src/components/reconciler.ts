/**
 * Keyed list reconciler for efficient DOM updates.
 *
 * Reconciles a list of data items against existing DOM children using keys.
 * Handles insert, update, remove, and reorder operations with minimal DOM mutations.
 */
export function reconcileList<T>(
  container: HTMLElement,
  items: T[],
  getKey: (item: T) => string,
  create: (item: T) => HTMLElement,
  update: (el: HTMLElement, item: T) => void,
  options?: { onRemove?: (el: HTMLElement) => Promise<void> },
): void {
  // Build a map of existing keyed children
  const existingByKey = new Map<string, HTMLElement>();
  const childArray = Array.from(container.children) as HTMLElement[];
  for (const child of childArray) {
    const key = child.dataset.key;
    if (key) {
      existingByKey.set(key, child);
    }
  }

  // Track which keys are in the new list
  const newKeys = new Set<string>();

  // Process items in order
  let currentNode: Element | null = container.firstElementChild;

  for (const item of items) {
    const key = getKey(item);
    newKeys.add(key);

    const existingEl = existingByKey.get(key);

    if (existingEl) {
      // Element exists — update it
      update(existingEl, item);

      if (existingEl !== currentNode) {
        // Element is out of position — move it
        container.insertBefore(existingEl, currentNode);
      } else {
        currentNode = currentNode.nextElementSibling;
      }
    } else {
      // New element — create and insert at correct position
      const newEl = create(item);
      newEl.dataset.key = key;
      container.insertBefore(newEl, currentNode);
    }
  }

  // Remove elements that are no longer in the list
  for (const [key, el] of existingByKey) {
    if (!newKeys.has(key)) {
      if (options?.onRemove) {
        // Async removal (for exit animations)
        options.onRemove(el).then(() => {
          if (el.parentNode === container) {
            container.removeChild(el);
          }
        });
      } else {
        container.removeChild(el);
      }
    }
  }
}
