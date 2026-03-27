/**
 * DialogManager — listens to store.openDialog and mounts/unmounts
 * dialog components as modal overlays in the #dialog-container element.
 *
 * Also listens to quickBlockOpen for backwards compatibility with
 * the shortcut service dispatching TOGGLE_QUICK_BLOCK.
 */

import { Component } from '../base';
import type { Store } from '../../store/index';
import type { AppState, DialogType } from '../../store/types';
import { AddHostDialog } from './add-host';
import { QuickBlockDialog } from './quick-block';
import { CreateGroupDialog } from './create-group';
import { CreateIpListDialog } from './create-iplist';
import { FirstSetupDialog } from './first-setup';
import type { FirstSetupConfig } from './first-setup';
import { MultiApplyDialog } from './multi-apply';
import { CompareHostsDialog } from './compare-hosts';
import { selectActiveHost } from '../../store/selectors';

export class DialogManager extends Component {
  private currentDialog: Component | null = null;
  private currentDialogType: DialogType = null;

  constructor(container: HTMLElement, store: Store) {
    super(container, store);

    // Listen for OPEN_DIALOG / CLOSE_DIALOG
    this.subscribe(
      (s: AppState) => s.openDialog,
      (dialog) => this.onDialogChanged(dialog),
    );

    // Listen for TOGGLE_QUICK_BLOCK (from shortcut service)
    this.subscribe(
      (s: AppState) => s.quickBlockOpen,
      (open) => {
        if (open && this.currentDialogType !== 'quick-block') {
          this.store.dispatch({ type: 'OPEN_DIALOG', dialog: 'quick-block' });
        } else if (!open && this.currentDialogType === 'quick-block') {
          this.store.dispatch({ type: 'CLOSE_DIALOG' });
        }
      },
    );
  }

  private onDialogChanged(dialog: DialogType): void {
    // Tear down current dialog if any
    if (this.currentDialog) {
      this.removeChild(this.currentDialog);
      this.currentDialog = null;
      this.currentDialogType = null;
    }

    if (!dialog) return;

    this.currentDialogType = dialog;

    switch (dialog) {
      case 'add-host': {
        const dlg = new AddHostDialog(this.el, this.store);
        dlg.onClose(() => {
          this.store.dispatch({ type: 'CLOSE_DIALOG' });
        });
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
      case 'quick-block': {
        // QuickBlockDialog closes itself by dispatching TOGGLE_QUICK_BLOCK.
        // The top-level subscription above detects quickBlockOpen=false
        // and dispatches CLOSE_DIALOG.
        const dlg = new QuickBlockDialog(this.el, this.store);
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
      case 'create-group': {
        const dlg = new CreateGroupDialog(this.el, this.store);
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
      case 'create-iplist': {
        const dlg = new CreateIpListDialog(this.el, this.store);
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
      case 'first-setup': {
        const host = this.store.select(selectActiveHost);
        if (!host) {
          this.store.dispatch({ type: 'CLOSE_DIALOG' });
          break;
        }

        const config: FirstSetupConfig = {
          hostId: host.id,
          hostName: host.name,
          scenario: 'clean',
          services: host.capabilities?.runningServices ?? [],
          existingRuleCount: 0,
          ruleHealthGood: 0,
          ruleHealthWarnings: [],
          ruleHealthSuggestions: [],
          detectedTools: host.capabilities?.detectedTools ?? [],
          suggestedRules: [],
          managementIp: undefined,
        };

        const dlg = new FirstSetupDialog(this.el, this.store, config);
        dlg.onComplete((selectedRules) => {
          for (let i = 0; i < selectedRules.length; i++) {
            this.store.dispatch({
              type: 'ADD_STAGED_CHANGE',
              hostId: host.id,
              change: { type: 'add', rule: selectedRules[i], position: i },
            });
          }
        });
        dlg.onSkip(() => {
          // User skipped — no action needed
        });
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
      case 'multi-apply': {
        const dlg = new MultiApplyDialog(this.el, this.store);
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
      case 'compare-hosts': {
        const dlg = new CompareHostsDialog(this.el, this.store);
        this.currentDialog = dlg;
        this.addChild(dlg);
        break;
      }
    }
  }
}
