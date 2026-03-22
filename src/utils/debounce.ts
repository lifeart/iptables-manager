/**
 * Debounce a function — delays invocation until `ms` milliseconds
 * have elapsed since the last call.
 */
export function debounce<T extends (...args: any[]) => void>(fn: T, ms: number): T {
  let timerId: ReturnType<typeof setTimeout> | undefined;

  const debounced = (...args: any[]) => {
    if (timerId !== undefined) {
      clearTimeout(timerId);
    }
    timerId = setTimeout(() => {
      timerId = undefined;
      fn(...args);
    }, ms);
  };

  return debounced as unknown as T;
}
