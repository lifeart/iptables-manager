/**
 * Animation utilities using the Web Animations API.
 *
 * Currently unused — kept as a utility for future component transitions.
 */

/**
 * Fade an element in (opacity 0 -> 1).
 */
export function fadeIn(el: HTMLElement, duration = 200): Promise<void> {
  el.style.display = '';
  const animation = el.animate(
    [{ opacity: 0 }, { opacity: 1 }],
    { duration, easing: 'ease-in-out', fill: 'forwards' },
  );
  return animation.finished.then(() => {
    el.style.opacity = '1';
  });
}

/**
 * Fade an element out (opacity 1 -> 0).
 */
export function fadeOut(el: HTMLElement, duration = 200): Promise<void> {
  const animation = el.animate(
    [{ opacity: 1 }, { opacity: 0 }],
    { duration, easing: 'ease-in-out', fill: 'forwards' },
  );
  return animation.finished.then(() => {
    el.style.opacity = '0';
    el.style.display = 'none';
  });
}

/**
 * Slide an element down (expand from height 0 to auto).
 */
export function slideDown(el: HTMLElement, duration = 250): Promise<void> {
  el.style.display = '';
  el.style.overflow = 'hidden';

  // Measure natural height
  const naturalHeight = el.scrollHeight;

  const animation = el.animate(
    [
      { height: '0px', opacity: 0 },
      { height: `${naturalHeight}px`, opacity: 1 },
    ],
    { duration, easing: 'ease-out', fill: 'forwards' },
  );

  return animation.finished.then(() => {
    el.style.height = '';
    el.style.overflow = '';
    el.style.opacity = '1';
  });
}

/**
 * Slide an element up (collapse from current height to 0).
 */
export function slideUp(el: HTMLElement, duration = 250): Promise<void> {
  el.style.overflow = 'hidden';
  const currentHeight = el.scrollHeight;

  const animation = el.animate(
    [
      { height: `${currentHeight}px`, opacity: 1 },
      { height: '0px', opacity: 0 },
    ],
    { duration, easing: 'ease-in', fill: 'forwards' },
  );

  return animation.finished.then(() => {
    el.style.display = 'none';
    el.style.height = '';
    el.style.overflow = '';
    el.style.opacity = '0';
  });
}
