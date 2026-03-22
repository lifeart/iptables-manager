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
        // FirstSetupDialog requires a FirstSetupConfig which is built
        // from host detection results. Close the dialog since there is
        // no config to display without an active detection flow.
        this.store.dispatch({ type: 'CLOSE_DIALOG' });
        break;
      }
    }
  }
}
