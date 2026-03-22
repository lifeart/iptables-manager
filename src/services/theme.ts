/**
 * Theme manager — light/dark/system with data-theme attribute.
 *
 * System preference is the default. User can override with explicit light/dark.
 * The data-theme attribute on <html> is used for CSS targeting.
 */

export type Theme = 'light' | 'dark' | 'system';

type ThemeChangeCallback = (resolved: 'light' | 'dark') => void;

class ThemeManager {
  private current: Theme = 'system';
  private mediaQuery: MediaQueryList | null = null;
  private listeners = new Set<ThemeChangeCallback>();
  private boundMediaHandler: (() => void) | null = null;

  /**
   * Initialize the theme manager.
   * Call once at startup after settings are loaded.
   */
  init(theme: Theme = 'system'): void {
    this.current = theme;

    // Set up system preference listener
    if (typeof window !== 'undefined' && window.matchMedia) {
      this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      this.boundMediaHandler = () => this.apply();
      this.mediaQuery.addEventListener('change', this.boundMediaHandler);
    }

    this.apply();
  }

  /**
   * Set the theme and apply it.
   */
  setTheme(theme: Theme): void {
    this.current = theme;
    this.apply();
  }

  /**
   * Get the current theme setting.
   */
  getTheme(): Theme {
    return this.current;
  }

  /**
   * Get the resolved theme (always 'light' or 'dark').
   */
  getResolvedTheme(): 'light' | 'dark' {
    if (this.current === 'system') {
      return this.getSystemPreference();
    }
    return this.current;
  }

  /**
   * Subscribe to theme changes (resolved value).
   */
  onChange(callback: ThemeChangeCallback): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  /**
   * Clean up event listeners.
   */
  destroy(): void {
    if (this.mediaQuery && this.boundMediaHandler) {
      this.mediaQuery.removeEventListener('change', this.boundMediaHandler);
    }
    this.listeners.clear();
  }

  private getSystemPreference(): 'light' | 'dark' {
    if (this.mediaQuery) {
      return this.mediaQuery.matches ? 'dark' : 'light';
    }
    return 'light';
  }

  private apply(): void {
    if (typeof document === 'undefined') return;

    const root = document.documentElement;

    if (this.current === 'system') {
      // Remove data-theme — CSS media query handles it
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', this.current);
    }

    const resolved = this.getResolvedTheme();
    for (const listener of this.listeners) {
      try {
        listener(resolved);
      } catch {
        // Theme change listener error — non-critical
      }
    }
  }
}

// Singleton
export const themeManager = new ThemeManager();
