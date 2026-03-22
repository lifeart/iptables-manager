import type { AppState } from './types';
import type { Action } from './actions';
import { createInitialState } from './types';
import { reducer } from './reducers';

export type Unsubscribe = () => void;

interface SelectorSubscription<R> {
  selector: (s: AppState) => R;
  callback: (val: R, prev: R) => void;
  lastValue: R;
}

export class Store {
  private state: AppState;
  private subscriptions = new Set<SelectorSubscription<unknown>>();
  private isDispatching = false;
  private pendingActions: Action[] = [];

  constructor(initialState?: AppState) {
    this.state = initialState ?? createInitialState();
  }

  getState(): AppState {
    return this.state;
  }

  dispatch(action: Action): void {
    if (this.isDispatching) {
      this.pendingActions.push(action);
      return;
    }

    this.isDispatching = true;

    try {
      const prevState = this.state;
      this.state = reducer(prevState, action);

      if (this.state !== prevState) {
        // Notify subscribers whose selected value changed
        for (const sub of this.subscriptions) {
          const newValue = sub.selector(this.state);
          const prevValue = sub.lastValue;
          if (newValue !== prevValue) {
            sub.lastValue = newValue;
            sub.callback(newValue, prevValue);
          }
        }
      }
    } finally {
      this.isDispatching = false;
    }

    // Process any actions queued during notification
    while (this.pendingActions.length > 0) {
      const next = this.pendingActions.shift()!;
      this.dispatch(next);
    }
  }

  /**
   * Subscribe with a selector — callback only fires when selected value changes.
   * Uses === reference equality for change detection.
   * Returns an unsubscribe function.
   */
  subscribeSelector<R>(
    selector: (s: AppState) => R,
    callback: (val: R, prev: R) => void,
  ): Unsubscribe {
    const sub: SelectorSubscription<unknown> = {
      selector: selector as (s: AppState) => unknown,
      callback: callback as (val: unknown, prev: unknown) => void,
      lastValue: selector(this.state),
    };
    this.subscriptions.add(sub);

    return () => {
      this.subscriptions.delete(sub);
    };
  }

  /**
   * Get current value from a selector.
   */
  select<R>(selector: (s: AppState) => R): R {
    return selector(this.state);
  }
}

// Singleton store instance
export const store = new Store();
