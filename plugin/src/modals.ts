import path from 'node:path';
import { App, Modal, Notice } from 'obsidian';
import type { CliBridge } from './cli-bridge';
import type { SearchItem, SearchResponse } from './types';
import { extractEventWikilinks, formatWikilinkTarget } from './diff-utils';

export class QuickSearchModal extends Modal {
  private bridge: CliBridge;
  private openTarget: (filePath: string, anchorTarget?: string) => Promise<void>;
  private resultsEl!: HTMLElement;
  private inputEl!: HTMLInputElement;
  private projectInputEl!: HTMLInputElement;
  private sourceSelectEl!: HTMLSelectElement;
  private statusEl!: HTMLElement;
  private items: SearchItem[] = [];
  private selectedIdx = 0;
  private lastSearchedQuery = '';
  private lastSearchedProject = '';
  private lastSearchedSource = 'all';

  constructor(
    app: App,
    bridge: CliBridge,
    openTarget: (filePath: string, anchorTarget?: string) => Promise<void>
  ) {
    super(app);
    this.bridge = bridge;
    this.openTarget = openTarget;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h3', { text: 'MindLoom Quick Search (Mode 0 · Zero Egress)' });

    const controls = contentEl.createDiv({ cls: 'mindloom-actions' });
    this.inputEl = controls.createEl('input', {
      type: 'text',
      placeholder: 'Search knowledge notes, errors, commands...'
    });
    this.inputEl.style.flex = '1';

    this.projectInputEl = controls.createEl('input', {
      type: 'text',
      placeholder: 'Project (optional)'
    });
    this.projectInputEl.style.width = '140px';

    this.sourceSelectEl = controls.createEl('select');
    for (const opt of ['all', 'codex', 'antigravity', 'dsh']) {
      this.sourceSelectEl.createEl('option', { value: opt, text: opt });
    }

    const searchBtn = controls.createEl('button', { text: 'Search', cls: 'mod-cta' });
    this.statusEl = contentEl.createDiv({ cls: 'mindloom-muted' });
    this.statusEl.style.marginTop = '6px';
    this.statusEl.setText('Enter to search · ↑↓ to select · Enter again (or Ctrl+Enter) to open · Shift+Enter to jump ^event');
    this.resultsEl = contentEl.createDiv();
    this.resultsEl.style.marginTop = '8px';
    this.resultsEl.style.maxHeight = '380px';
    this.resultsEl.style.overflowY = 'auto';

    const runSearch = async () => {
      const q = this.inputEl.value.trim();
      if (!q) return;
      this.statusEl.setText('Searching (Mode 0 literal)...');
      const args = ['search', q, '--mode', 'literal'];
      const proj = this.projectInputEl.value.trim();
      if (proj) args.push('--project', proj);
      const src = this.sourceSelectEl.value;
      if (src && src !== 'all') args.push('--source', src);

      const res = await this.bridge.runJson<SearchResponse>(args);
      if (!res.ok || !res.data) {
        this.statusEl.setText(`Error: ${res.error || 'search failed'}`);
        this.resultsEl.empty();
        return;
      }
      this.lastSearchedQuery = q;
      this.lastSearchedProject = proj;
      this.lastSearchedSource = src;
      this.items = res.data.items || [];
      this.selectedIdx = 0;
      this.statusEl.setText(
        res.data.noAnswer
          ? 'No sanitized matches found (Mode 0 literal).'
          : `Found ${this.items.length} result(s) · Mode: ${res.data.mode} · Enter to open selected`
      );
      this.renderResults();
    };

    const openSelected = (preferAnchor: boolean) => {
      const item = this.items[this.selectedIdx];
      if (!item) return;
      const anchors = extractEventWikilinks([...(item.event_anchors || []), ...(item.sources || [])]);
      this.close();
      void this.openTarget(item.path, preferAnchor && anchors.length > 0 ? anchors[0] : undefined);
    };

    searchBtn.addEventListener('click', () => void runSearch());
    this.inputEl.addEventListener('keydown', (ev: KeyboardEvent) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        const sameQuery =
          this.inputEl.value.trim() === this.lastSearchedQuery &&
          this.projectInputEl.value.trim() === this.lastSearchedProject &&
          this.sourceSelectEl.value === this.lastSearchedSource;
        if (this.items.length > 0 && (ev.ctrlKey || ev.shiftKey || sameQuery)) {
          openSelected(ev.shiftKey);
        } else {
          void runSearch();
        }
      } else if (ev.key === 'ArrowDown' && this.items.length > 0) {
        ev.preventDefault();
        this.selectedIdx = Math.min(this.items.length - 1, this.selectedIdx + 1);
        this.renderResults();
      } else if (ev.key === 'ArrowUp' && this.items.length > 0) {
        ev.preventDefault();
        this.selectedIdx = Math.max(0, this.selectedIdx - 1);
        this.renderResults();
      }
    });

    setTimeout(() => this.inputEl.focus(), 20);
  }

  private renderResults(): void {
    this.resultsEl.empty();
    this.items.forEach((item, idx) => {
      const row = this.resultsEl.createDiv({ cls: 'mindloom-search-result' });
      if (idx === this.selectedIdx) {
        row.style.backgroundColor = 'var(--background-modifier-hover)';
      }

      const titleLine = row.createDiv();
      const badge = titleLine.createSpan({
        cls: `mindloom-badge ${item.actionable ? 'mindloom-badge-ok' : 'mindloom-badge-warn'}`,
        text: item.actionable ? 'Channel 1 · Actionable' : 'Channel 2 · Reference'
      });
      badge.title = item.reason || '';

      const titleLink = titleLine.createEl('a', { text: item.title || item.id });
      titleLink.style.fontWeight = '600';
      titleLink.style.cursor = 'pointer';
      titleLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.close();
        void this.openTarget(item.path);
      });

      const tools = item.derived_source_tools?.length ? item.derived_source_tools.join(', ') : 'local';
      const meta = row.createDiv({
        cls: 'mindloom-search-meta',
        text: `${item.id} · project=${item.project || 'unmapped'} · source=${tools}${item.reason ? ` · ${item.reason}` : ''}`
      });
      if (item.injectionDetected) {
        meta.createSpan({
          cls: 'mindloom-badge mindloom-badge-err',
          text: 'Prompt Injection Guarded'
        });
      }

      if (item.snippet) {
        row.createDiv({ cls: 'mindloom-muted', text: item.snippet });
      }

      const anchors = extractEventWikilinks([...(item.event_anchors || []), ...(item.sources || [])]);
      if (anchors.length > 0 || (item.sources && item.sources.length > 0)) {
        const srcRow = row.createDiv({ cls: 'mindloom-actions' });
        srcRow.style.marginTop = '4px';
        for (const anchorTarget of anchors.slice(0, 3)) {
          const btn = srcRow.createEl('button', {
            text: `Jump ${anchorTarget.split('#')[1] || '^event'}`
          });
          btn.addEventListener('click', () => {
            this.close();
            void this.openTarget(item.path, anchorTarget);
          });
        }
        if (anchors.length === 0 && item.sources) {
          for (const rawSrc of item.sources.slice(0, 2)) {
            const cleanTarget = formatWikilinkTarget(rawSrc);
            if (!cleanTarget) continue;
            const btn = srcRow.createEl('button', {
              text: `Open ${path.basename(cleanTarget)}`
            });
            btn.addEventListener('click', () => {
              this.close();
              void this.openTarget(item.path, cleanTarget);
            });
          }
        }
      }
    });
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

export class AdminCommandModal extends Modal {
  private titleText: string;
  private description: string;
  private commandText: string;

  constructor(app: App, titleText: string, description: string, commandText: string) {
    super(app);
    this.titleText = titleText;
    this.description = description;
    this.commandText = commandText;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h3', { text: this.titleText });
    contentEl.createEl('p', { text: this.description, cls: 'mindloom-muted' });
    contentEl.createDiv({ cls: 'mindloom-code-box', text: this.commandText });

    const btnRow = contentEl.createDiv({ cls: 'mindloom-actions' });
    btnRow.style.marginTop = '12px';
    const copyBtn = btnRow.createEl('button', { text: 'Copy Command', cls: 'mod-cta' });
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(this.commandText);
        new Notice('Administrator terminal command copied to clipboard.');
      } catch {
        new Notice('Copy failed; please select the command text manually.');
      }
    });
    const closeBtn = btnRow.createEl('button', { text: 'Close' });
    closeBtn.addEventListener('click', () => this.close());
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

export class ConfirmRestoreModal extends Modal {
  private noteId: string;
  private revision: string;
  private onConfirm: () => Promise<void>;

  constructor(app: App, noteId: string, revision: string, onConfirm: () => Promise<void>) {
    super(app);
    this.noteId = noteId;
    this.revision = revision;
    this.onConfirm = onConfirm;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h3', { text: `Confirm Atomic Restore: ${this.noteId}` });
    contentEl.createEl('p', {
      text: `This will run "mem restore ${this.noteId} --revision ${this.revision} --confirm" to atomically restore the note (and lift its tombstone if deleted). Existing non-deleted notes will NOT be overwritten.`
    });
    const actions = contentEl.createDiv({ cls: 'mindloom-actions' });
    const confirmBtn = actions.createEl('button', { text: 'Confirm Restore', cls: 'mod-warning' });
    confirmBtn.addEventListener('click', async () => {
      confirmBtn.disabled = true;
      try {
        await this.onConfirm();
        this.close();
      } finally {
        confirmBtn.disabled = false;
      }
    });
    const cancelBtn = actions.createEl('button', { text: 'Cancel' });
    cancelBtn.addEventListener('click', () => this.close());
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
