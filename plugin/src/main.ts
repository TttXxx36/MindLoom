import fs from 'node:fs';
import path from 'node:path';
import { FileSystemAdapter, Notice, Plugin, WorkspaceLeaf } from 'obsidian';
import { CliBridge } from './cli-bridge';
import { MindLoomConsoleView, VIEW_TYPE_MINDLOOM_CONSOLE } from './console-view';
import { QuickSearchModal } from './modals';
import { MindLoomSettingTab } from './settings-tab';
import { DEFAULT_SETTINGS, type MindLoomSettings, type StatusResponse } from './types';

export default class MindLoomPlugin extends Plugin {
  settings: MindLoomSettings = { ...DEFAULT_SETTINGS };
  bridge!: CliBridge;
  private statusBarEl!: HTMLElement;

  async onload(): Promise<void> {
    await this.loadSettings();

    this.bridge = new CliBridge(
      () => this.settings,
      () => this.getVaultBasePath()
    );

    this.registerView(VIEW_TYPE_MINDLOOM_CONSOLE, (leaf: WorkspaceLeaf) => new MindLoomConsoleView(leaf, this));

    this.statusBarEl = this.addStatusBarItem();
    this.statusBarEl.setText('MindLoom: loading...');
    this.statusBarEl.addEventListener('click', () => void this.activateConsoleView());

    this.addRibbonIcon('brain-circuit', 'Open MindLoom Console', () => {
      void this.activateConsoleView();
    });

    this.addCommand({
      id: 'mindloom-open-console',
      name: 'Open MindLoom Console',
      callback: () => void this.activateConsoleView()
    });

    this.addCommand({
      id: 'mindloom-open-home',
      name: 'Open Home Dashboard (首页.md)',
      callback: () => void this.openHomeNote()
    });

    this.addCommand({
      id: 'mindloom-open-digest',
      name: 'Open Latest Session Digest Brief',
      callback: () => void this.openDigestBrief()
    });

    this.addCommand({
      id: 'mindloom-quick-search',
      name: 'Quick Memory Search (Mode 0 · Zero Egress)',
      callback: () => this.openQuickSearch()
    });

    this.addCommand({
      id: 'mindloom-sync-rebuild-moc',
      name: 'Sync Whitelisted Sessions & Rebuild 00_MOC',
      callback: () => void this.runSyncAndRebuildMoc()
    });

    this.addSettingTab(new MindLoomSettingTab(this.app, this));

    this.app.workspace.onLayoutReady(() => {
      void this.refreshStatusBar();
    });
  }

  onunload(): void {
    // Workspace view cleanup handled by Obsidian
  }

  getVaultBasePath(): string {
    if (this.settings.vaultPath?.trim()) {
      return path.resolve(this.settings.vaultPath.trim());
    }
    const adapter = this.app.vault.adapter;
    if (adapter instanceof FileSystemAdapter) {
      return adapter.getBasePath();
    }
    return '';
  }

  async loadSettings(): Promise<void> {
    try {
      const loaded = (await this.loadData()) as Partial<MindLoomSettings> | null;
      if (loaded && typeof loaded === 'object' && !Array.isArray(loaded)) {
        this.settings = { ...DEFAULT_SETTINGS, ...loaded };
      } else {
        this.settings = { ...DEFAULT_SETTINGS };
      }
    } catch (err) {
      this.settings = { ...DEFAULT_SETTINGS };
      new Notice(
        `MindLoom: failed to parse plugin data.json (${err instanceof Error ? err.message : String(err)}); using defaults without overwriting file.`,
        8000
      );
    }
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
    await this.refreshStatusBar();
  }

  async activateConsoleView(): Promise<void> {
    const { workspace } = this.app;
    let leaf: WorkspaceLeaf | null = workspace.getLeavesOfType(VIEW_TYPE_MINDLOOM_CONSOLE)[0] || null;
    if (!leaf) {
      leaf = workspace.getRightLeaf(false);
      if (leaf) {
        await leaf.setViewState({ type: VIEW_TYPE_MINDLOOM_CONSOLE, active: true });
      }
    }
    if (leaf) {
      await workspace.revealLeaf(leaf);
    }
  }

  openQuickSearch(): void {
    new QuickSearchModal(this.app, this.bridge, async (filePath, anchorTarget) => {
      await this.openVaultFile(filePath, anchorTarget);
    }).open();
  }

  async openHomeNote(): Promise<void> {
    if (!this.app.vault.getAbstractFileByPath('首页.md')) {
      new Notice('首页.md not found in Vault. Run "mem setup" or "Sync & Rebuild MOC" first.');
      return;
    }
    await this.app.workspace.openLinkText('首页.md', '', false);
  }

  async openDigestBrief(): Promise<void> {
    const briefPath = '00_MOC/学习简报_最新会话精华.md';
    if (!this.app.vault.getAbstractFileByPath(briefPath)) {
      new Notice('Digest brief not generated yet. Click "Sync & Rebuild MOC" first.');
      return;
    }
    await this.app.workspace.openLinkText(briefPath, '', false);
  }

  async openVaultFile(absOrRelPath: string, anchorTarget?: string): Promise<void> {
    if (anchorTarget) {
      await this.app.workspace.openLinkText(anchorTarget, '', false);
      return;
    }
    const vaultBase = this.getVaultBasePath();
    let target = absOrRelPath;
    if (vaultBase && path.isAbsolute(absOrRelPath)) {
      const rel = path.relative(vaultBase, absOrRelPath).replace(/\\/g, '/');
      if (rel && !rel.startsWith('..')) {
        target = rel;
      }
    }
    await this.app.workspace.openLinkText(target, '', false);
  }

  async runSyncAndRebuildMoc(): Promise<void> {
    new Notice('MindLoom: syncing whitelisted sessions & rebuilding 00_MOC...');
    const syncRes = await this.bridge.runJson<{
      syncedCount?: number;
      alreadySyncedCount?: number;
      skippedUnmappedCount?: number;
      skippedUnapprovedCount?: number;
      errorsCount?: number;
      mocUpdated?: boolean;
    }>(['auto-sync', '--no-moc']);

    if (!syncRes.ok || !syncRes.data) {
      new Notice(`MindLoom Sync failed: ${syncRes.error || 'unknown error'}`, 8000);
    } else {
      const d = syncRes.data;
      const synced = d.syncedCount ?? 0;
      const errCount = d.errorsCount ?? 0;
      const unapproved = d.skippedUnapprovedCount ?? 0;
      const unmapped = d.skippedUnmappedCount ?? 0;
      if (errCount > 0 || unapproved > 0) {
        new Notice(
          `MindLoom Sync completed with warnings: synced=${synced}, errors=${errCount}, unapproved=${unapproved}, unmapped=${unmapped}.`,
          8000
        );
      } else {
        new Notice(`MindLoom Sync: synced=${synced}, unmapped=${unmapped}.`);
      }
    }

    if (!syncRes.ok || !syncRes.data?.mocUpdated) {
      const mocRes = await this.bridge.runJson<{ projectsCount?: number; sanitizedNotesCount?: number }>([
        'render-moc',
        '--update-digests'
      ]);
      if (mocRes.ok && mocRes.data) {
        new Notice(
          `MindLoom MOC rebuilt: ${mocRes.data.projectsCount ?? 0} projects, ${mocRes.data.sanitizedNotesCount ?? 0} notes.`
        );
      } else {
        new Notice(`MindLoom MOC rebuild failed: ${mocRes.error || 'unknown error'}`, 8000);
      }
    } else {
      new Notice('MindLoom MOC already updated by auto-sync.');
    }

    await this.refreshStatusBar();
    for (const leaf of this.app.workspace.getLeavesOfType(VIEW_TYPE_MINDLOOM_CONSOLE)) {
      if (leaf.view instanceof MindLoomConsoleView) {
        await leaf.view.render();
      }
    }
  }

  async refreshStatusBar(): Promise<void> {
    const { dataPath } = this.bridge.resolvePaths();
    const dbExists = Boolean(dataPath && fs.existsSync(path.join(dataPath, 'runtime', 'state.sqlite')));
    if (!dbExists) {
      this.statusBarEl.setText('MindLoom: not initialized');
      return;
    }
    const res = await this.bridge.runJson<StatusResponse>(['status'], { timeoutMs: 8000 });
    if (!res.ok || !res.data) {
      this.statusBarEl.setText('MindLoom: CLI offline');
      return;
    }
    const st = res.data;
    const lastSync = this.bridge.readLastAutoSyncTime();
    const syncLabel = lastSync ? ` · sync ${lastSync.slice(0, 10)}` : '';
    this.statusBarEl.setText(
      `MindLoom: ${st.notes.total} notes · ${st.proposals.pending} pending${syncLabel}`
    );
  }
}
