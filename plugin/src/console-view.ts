import { ItemView, Notice, WorkspaceLeaf } from 'obsidian';
import type MindLoomPlugin from './main';
import type {
  CloudBudgetResponse,
  ProjectMapEntry,
  ProjectMapResponse,
  ProposalShowResponse,
  RestoreDetailResponse,
  RestoreListResponse,
  StatusResponse
} from './types';
import { computeSimpleLineDiff } from './diff-utils';
import { AdminCommandModal, ConfirmRestoreModal } from './modals';

export const VIEW_TYPE_MINDLOOM_CONSOLE = 'mindloom-console-view';

type ConsoleTab = 'proposals' | 'restore' | 'whitelist' | 'budget';

export class MindLoomConsoleView extends ItemView {
  private plugin: MindLoomPlugin;
  private activeTab: ConsoleTab = 'proposals';
  private selectedProposal: ProposalShowResponse | null = null;
  private selectedRestorePreview: RestoreDetailResponse | null = null;
  private editingEntry: ProjectMapEntry | null = null;

  constructor(leaf: WorkspaceLeaf, plugin: MindLoomPlugin) {
    super(leaf);
    this.plugin = plugin;
  }

  getViewType(): string {
    return VIEW_TYPE_MINDLOOM_CONSOLE;
  }

  getDisplayText(): string {
    return 'MindLoom Console';
  }

  getIcon(): string {
    return 'brain-circuit';
  }

  async onOpen(): Promise<void> {
    await this.render();
  }

  async setTab(tab: ConsoleTab): Promise<void> {
    this.activeTab = tab;
    await this.render();
  }

  async render(): Promise<void> {
    const container = this.containerEl.children[1] as HTMLElement | undefined;
    if (!container) return;
    container.empty();
    container.addClass('mindloom-console');

    const header = container.createDiv({ cls: 'mindloom-header' });
    header.createEl('h2', { text: 'MindLoom Console', cls: 'mindloom-title' });

    const quickBar = header.createDiv({ cls: 'mindloom-actions' });
    const homeBtn = quickBar.createEl('button', { text: 'Home' });
    homeBtn.addEventListener('click', () => void this.plugin.openHomeNote());

    const digestBtn = quickBar.createEl('button', { text: 'Digest' });
    digestBtn.addEventListener('click', () => void this.plugin.openDigestBrief());

    const searchBtn = quickBar.createEl('button', { text: 'Search' });
    searchBtn.addEventListener('click', () => this.plugin.openQuickSearch());

    const syncBtn = quickBar.createEl('button', { text: 'Sync & Rebuild MOC', cls: 'mod-cta' });
    syncBtn.addEventListener('click', () => void this.plugin.runSyncAndRebuildMoc());

    const tabBar = container.createDiv({ cls: 'mindloom-tabs' });
    const tabs: Array<{ id: ConsoleTab; label: string }> = [
      { id: 'proposals', label: 'Proposals & Diff' },
      { id: 'restore', label: 'Tombstones & Restore' },
      { id: 'whitelist', label: 'Whitelist (project-map)' },
      { id: 'budget', label: 'Cloud Budget (Read-Only)' }
    ];
    for (const t of tabs) {
      const btn = tabBar.createEl('button', {
        text: t.label,
        cls: `mindloom-tab-btn ${this.activeTab === t.id ? 'is-active' : ''}`
      });
      btn.addEventListener('click', () => void this.setTab(t.id));
    }

    const body = container.createDiv();
    if (this.activeTab === 'proposals') {
      await this.renderProposalsTab(body);
    } else if (this.activeTab === 'restore') {
      await this.renderRestoreTab(body);
    } else if (this.activeTab === 'whitelist') {
      await this.renderWhitelistTab(body);
    } else {
      await this.renderBudgetTab(body);
    }
  }

  private async renderProposalsTab(parent: HTMLElement): Promise<void> {
    const topRow = parent.createDiv({ cls: 'mindloom-actions' });
    topRow.style.marginBottom = '10px';
    const refreshBtn = topRow.createEl('button', { text: 'Refresh Status' });
    refreshBtn.addEventListener('click', () => void this.render());

    const reconcileBtn = topRow.createEl('button', { text: 'Run mem reconcile', cls: 'mod-cta' });
    reconcileBtn.addEventListener('click', async () => {
      reconcileBtn.disabled = true;
      try {
        const res = await this.plugin.bridge.runJson<{
          proposals?: { checked: number; applied: number; conflictsCount: number };
        }>(['reconcile']);
        if (res.ok && res.data) {
          const p = res.data.proposals;
          new Notice(`Reconcile complete: checked=${p?.checked ?? 0}, verified=${p?.applied ?? 0}`);
          if (this.selectedProposal) {
            const refreshed = await this.plugin.bridge.runJson<ProposalShowResponse>([
              'proposal',
              'show',
              this.selectedProposal.id
            ]);
            this.selectedProposal = refreshed.ok && refreshed.data ? refreshed.data : null;
          }
          await this.plugin.refreshStatusBar();
          await this.render();
        } else {
          new Notice(`Reconcile failed: ${res.error}`);
        }
      } finally {
        reconcileBtn.disabled = false;
      }
    });

    const statusRes = await this.plugin.bridge.runJson<StatusResponse>(['status']);
    if (!statusRes.ok || !statusRes.data) {
      parent.createDiv({ cls: 'mindloom-card', text: `Failed to load status: ${statusRes.error || 'unknown error'}` });
      return;
    }

    const st = statusRes.data;
    const summaryCard = parent.createDiv({ cls: 'mindloom-card' });
    summaryCard.createEl('div', {
      text: `Notes: ${st.notes.total} (Knowledge: ${st.notes.byType.knowledge}, Sessions: ${st.notes.byType.sessions}) · Pending Proposals: ${st.proposals.pending} · Verified: ${st.proposals.verified} · Conflicts: ${st.proposals.conflictCount}`
    });

    const pending = st.proposals.pendingDetails || [];
    const details = st.proposals.details || [];
    const combinedIds = new Set<string>();
    for (const p of pending) combinedIds.add(p.proposal_id);
    for (const d of details) combinedIds.add(d.proposal_id);

    if (combinedIds.size === 0) {
      parent.createDiv({ cls: 'mindloom-card', text: 'No pending or tracked proposals in 40_Review_Queue/.' });
    } else {
      for (const p of pending) {
        this.renderProposalCard(parent, p.proposal_id, p.target_id, 'pending', null, p.path);
      }
      for (const d of details) {
        if (pending.some((p) => p.proposal_id === d.proposal_id)) continue;
        this.renderProposalCard(parent, d.proposal_id, d.target_id, d.reconcile_state || 'tracked', d.reason || null);
      }
    }

    if (this.selectedProposal) {
      const prop = this.selectedProposal;
      const detailCard = parent.createDiv({ cls: 'mindloom-card' });
      detailCard.createEl('h4', { text: `Proposal Diff Preview: ${prop.id} -> ${prop.target_id}` });
      detailCard.createDiv({
        cls: 'mindloom-muted',
        text: `Status=${prop.proposal_status} · Reconcile=${prop.reconcile_state}${prop.reconcile_reason ? ` (${prop.reconcile_reason})` : ''} · BaseRev=${prop.base_revision_id}`
      });

      if (prop.condition_checks) {
        const condWrap = detailCard.createDiv();
        condWrap.style.marginTop = '6px';
        condWrap.createSpan({
          cls: `mindloom-badge ${prop.condition_checks.passed ? 'mindloom-badge-ok' : 'mindloom-badge-warn'}`,
          text: prop.condition_checks.passed ? 'Pre/Post Conditions Satisfied' : 'Conditions Pending'
        });
        for (const preCond of prop.condition_checks.pre_conditions || []) {
          const ok = Boolean(preCond.passed ?? preCond.satisfied);
          condWrap.createDiv({
            cls: 'mindloom-muted',
            text: `${ok ? '✔' : '✖'} [pre] ${preCond.text || ''}`
          });
        }
        for (const postCond of prop.condition_checks.post_conditions || []) {
          const ok = Boolean(postCond.passed ?? postCond.satisfied);
          condWrap.createDiv({
            cls: 'mindloom-muted',
            text: `${ok ? '✔' : '✖'} [post] ${postCond.text || ''}`
          });
        }
      }

      if (prop.path || prop.target_path) {
        const linkRow = detailCard.createDiv({ cls: 'mindloom-actions' });
        linkRow.style.marginTop = '6px';
        if (prop.path && prop.path !== '[REDACTED_LOCAL_ONLY]') {
          const openPropBtn = linkRow.createEl('button', { text: 'Open Proposal Note' });
          openPropBtn.addEventListener('click', () => void this.plugin.openVaultFile(prop.path!));
        }
        if (prop.target_path && prop.target_path !== '[REDACTED_LOCAL_ONLY]') {
          const openTargetBtn = linkRow.createEl('button', { text: 'Open Target Note' });
          openTargetBtn.addEventListener('click', () => void this.plugin.openVaultFile(prop.target_path!));
        }
      }

      if (prop.base_revision_diff) {
        const d = prop.base_revision_diff;
        const pre = detailCard.createEl('pre', { cls: 'mindloom-diff-pre' });
        if (d.redacted) {
          pre.setText(`[REDACTED: ${d.reason || 'non-sanitized'}]`);
        } else if (!d.base_revision_found) {
          pre.setText(`Base revision not found (${d.reason || 'missing'})`);
        } else {
          const removed = d.removed_lines || [];
          const added = d.added_lines || [];
          if (removed.length === 0 && added.length === 0) {
            pre.setText('(No diff vs base revision)');
          } else {
            for (const rem of removed) {
              pre.createEl('div', { text: `- ${rem}`, cls: 'mindloom-diff-del' });
            }
            for (const add of added) {
              pre.createEl('div', { text: `+ ${add}`, cls: 'mindloom-diff-add' });
            }
          }
        }
      }

      const bodyPre = detailCard.createEl('pre', { cls: 'mindloom-diff-pre' });
      bodyPre.setText(prop.body || '');

      detailCard.createDiv({
        cls: 'mindloom-muted',
        text: 'Safe adoption guide: Review the diff above, update the target note in Obsidian, set proposal_status: "accepted" in the proposal frontmatter, then click "Run mem reconcile".'
      });
    }
  }

  private renderProposalCard(
    parent: HTMLElement,
    proposalId: string,
    targetId: string | null,
    stateLabel: string,
    reason: string | null,
    notePath?: string
  ): void {
    const card = parent.createDiv({ cls: 'mindloom-card' });
    const badgeCls =
      stateLabel === 'verified_applied'
        ? 'mindloom-badge-ok'
        : stateLabel === 'mismatch' || reason === 'version_changed'
          ? 'mindloom-badge-err'
          : 'mindloom-badge-warn';

    card.createSpan({ cls: `mindloom-badge ${badgeCls}`, text: stateLabel });
    card.createSpan({ text: `${proposalId} -> ${targetId || 'unknown'}` });
    if (reason) {
      card.createDiv({ cls: 'mindloom-muted', text: `Reason: ${reason}` });
    }

    const actions = card.createDiv({ cls: 'mindloom-actions' });
    actions.style.marginTop = '6px';
    const previewBtn = actions.createEl('button', { text: 'Inspect Diff & Conditions' });
    previewBtn.addEventListener('click', async () => {
      const res = await this.plugin.bridge.runJson<ProposalShowResponse>(['proposal', 'show', proposalId]);
      if (res.ok && res.data) {
        this.selectedProposal = res.data;
        await this.render();
      } else {
        new Notice(`Cannot inspect ${proposalId}: ${res.error}`);
      }
    });

    if (notePath && notePath !== '[REDACTED_LOCAL_ONLY]') {
      const openBtn = actions.createEl('button', { text: 'Open Proposal Note' });
      openBtn.addEventListener('click', () => void this.plugin.openVaultFile(notePath));
    }
  }

  private async renderRestoreTab(parent: HTMLElement): Promise<void> {
    const lookupRow = parent.createDiv({ cls: 'mindloom-actions' });
    lookupRow.style.marginBottom = '10px';
    const idInput = lookupRow.createEl('input', {
      type: 'text',
      placeholder: 'Note ID (e.g. KN-...)'
    });
    idInput.style.flex = '1';
    const revInput = lookupRow.createEl('input', {
      type: 'text',
      placeholder: 'Revision (e.g. rev-0001)'
    });
    revInput.value = 'rev-0001';
    revInput.style.width = '120px';

    const previewBtn = lookupRow.createEl('button', { text: 'Preview Diff', cls: 'mod-cta' });
    previewBtn.addEventListener('click', async () => {
      const noteId = idInput.value.trim();
      const rev = revInput.value.trim() || 'rev-0001';
      if (!noteId) {
        new Notice('Enter a note ID to preview.');
        return;
      }
      const res = await this.plugin.bridge.runJson<RestoreDetailResponse>(['restore', noteId, '--revision', rev]);
      if (res.ok && res.data) {
        this.selectedRestorePreview = res.data;
        await this.render();
      } else {
        new Notice(`Preview failed: ${res.error}`);
      }
    });

    const listRes = await this.plugin.bridge.runJson<RestoreListResponse>(['restore', '--list']);
    if (!listRes.ok || !listRes.data) {
      parent.createDiv({ cls: 'mindloom-card', text: `Failed to list tombstoned/missing notes: ${listRes.error}` });
    } else if (listRes.data.items.length === 0) {
      parent.createDiv({ cls: 'mindloom-card', text: 'No deleted or missing notes currently pending restore.' });
    } else {
      for (const item of listRes.data.items) {
        const card = parent.createDiv({ cls: 'mindloom-card' });
        card.createSpan({ cls: 'mindloom-badge mindloom-badge-warn', text: item.status });
        card.createSpan({ text: `${item.title} (${item.id})` });
        card.createDiv({
          cls: 'mindloom-muted',
          text: `Project=${item.project} · Revisions=${item.revisions.join(', ') || 'git/none'}`
        });
        const btns = card.createDiv({ cls: 'mindloom-actions' });
        btns.style.marginTop = '6px';
        const revs = item.revisions.length > 0 ? item.revisions : ['rev-0001'];
        for (const rev of revs.slice(0, 4)) {
          const b = btns.createEl('button', { text: `Preview ${rev}` });
          b.addEventListener('click', async () => {
            const res = await this.plugin.bridge.runJson<RestoreDetailResponse>(['restore', item.id, '--revision', rev]);
            if (res.ok && res.data) {
              this.selectedRestorePreview = res.data;
              await this.render();
            } else {
              new Notice(`Preview failed: ${res.error}`);
            }
          });
        }
      }
    }

    if (this.selectedRestorePreview) {
      const rp = this.selectedRestorePreview;
      const card = parent.createDiv({ cls: 'mindloom-card' });
      card.createEl('h4', { text: `Restore Preview: ${rp.noteId} @ ${rp.revision}` });
      card.createDiv({
        cls: 'mindloom-muted',
        text: `Target: ${rp.targetPath} · Reason: ${rp.reason || 'ready'}`
      });

      const pre = card.createEl('pre', { cls: 'mindloom-diff-pre' });
      if (rp.redacted) {
        pre.setText('[REDACTED_LOCAL_ONLY: private note content cannot be previewed]');
      } else if (rp.currentDiskContent !== null) {
        const diffLines = computeSimpleLineDiff(rp.currentDiskContent, rp.revisionContent);
        for (const line of diffLines) {
          const span = pre.createEl('div', {
            text: line.text,
            cls: line.kind === 'add' ? 'mindloom-diff-add' : line.kind === 'del' ? 'mindloom-diff-del' : ''
          });
          void span;
        }
      } else {
        pre.setText(rp.revisionContent || '');
      }

      const actions = card.createDiv({ cls: 'mindloom-actions' });
      actions.style.marginTop = '8px';
      const restoreBtn = actions.createEl('button', { text: 'Restore Atomically...', cls: 'mod-warning' });
      restoreBtn.addEventListener('click', () => {
        new ConfirmRestoreModal(this.app, rp.noteId, rp.revision, async () => {
          const execRes = await this.plugin.bridge.runJson<RestoreDetailResponse>([
            'restore',
            rp.noteId,
            '--revision',
            rp.revision,
            '--confirm'
          ]);
          if (execRes.ok && execRes.data) {
            new Notice(
              execRes.data.restored
                ? `Restored ${rp.noteId} (${rp.revision}) successfully.`
                : `Preview updated (${execRes.data.reason || 'target exists'}).`
            );
            this.selectedRestorePreview = execRes.data;
            await this.plugin.refreshStatusBar();
            await this.render();
          } else {
            new Notice(`Restore failed: ${execRes.error}`);
          }
        }).open();
      });
    }
  }

  private async renderWhitelistTab(parent: HTMLElement): Promise<void> {
    const res = await this.plugin.bridge.runJson<ProjectMapResponse>(['project-map', 'list']);
    if (!res.ok || !res.data) {
      parent.createDiv({ cls: 'mindloom-card', text: `Failed to load project-map.json: ${res.error}` });
      return;
    }

    const projects = res.data.projects || [];
    for (const entry of projects) {
      const card = parent.createDiv({ cls: 'mindloom-card' });
      card.createEl('strong', { text: entry.project });
      card.createDiv({ cls: 'mindloom-muted', text: `Paths: ${(entry.paths || []).join(', ') || '(none)'}` });
      card.createDiv({ cls: 'mindloom-muted', text: `Git Roots: ${(entry.git_roots || []).join(', ') || '(none)'}` });
      card.createDiv({ cls: 'mindloom-muted', text: `Slugs: ${(entry.workspace_slugs || []).join(', ') || '(none)'}` });

      const actions = card.createDiv({ cls: 'mindloom-actions' });
      actions.style.marginTop = '6px';
      const editBtn = actions.createEl('button', { text: 'Edit' });
      editBtn.addEventListener('click', () => {
        this.editingEntry = { ...entry };
        void this.render();
      });
      const delBtn = actions.createEl('button', { text: 'Remove', cls: 'mod-warning' });
      delBtn.addEventListener('click', async () => {
        const rmRes = await this.plugin.bridge.runJson(['project-map', 'remove', '--project', entry.project]);
        if (rmRes.ok) {
          new Notice(`Removed project "${entry.project}" from whitelist.`);
          await this.render();
        } else {
          new Notice(`Remove failed: ${rmRes.error}`);
        }
      });
    }

    const formCard = parent.createDiv({ cls: 'mindloom-card' });
    formCard.createEl('h4', { text: this.editingEntry ? `Edit Project: ${this.editingEntry.project}` : 'Add Whitelist Project' });

    const nameRow = formCard.createDiv({ cls: 'mindloom-form-row' });
    nameRow.createEl('label', { text: 'Project Name' });
    const nameInput = nameRow.createEl('input', { type: 'text', placeholder: 'e.g. MyProject' });
    nameInput.value = this.editingEntry?.project || '';

    const pathsRow = formCard.createDiv({ cls: 'mindloom-form-row' });
    pathsRow.createEl('label', { text: 'Workspace Paths (comma-separated)' });
    const pathsInput = pathsRow.createEl('input', { type: 'text', placeholder: 'e.g. C:\\Work\\my-project' });
    pathsInput.value = (this.editingEntry?.paths || []).join(', ');

    const gitRow = formCard.createDiv({ cls: 'mindloom-form-row' });
    gitRow.createEl('label', { text: 'Git Roots (comma-separated, optional)' });
    const gitInput = gitRow.createEl('input', { type: 'text', placeholder: 'e.g. C:\\Work\\my-project' });
    gitInput.value = (this.editingEntry?.git_roots || []).join(', ');

    const slugRow = formCard.createDiv({ cls: 'mindloom-form-row' });
    slugRow.createEl('label', { text: 'Workspace Slugs (comma-separated, optional)' });
    const slugInput = slugRow.createEl('input', { type: 'text', placeholder: 'e.g. my-project' });
    slugInput.value = (this.editingEntry?.workspace_slugs || []).join(', ');

    const btnRow = formCard.createDiv({ cls: 'mindloom-actions' });
    const saveBtn = btnRow.createEl('button', { text: 'Validate & Save', cls: 'mod-cta' });
    saveBtn.addEventListener('click', async () => {
      const proj = nameInput.value.trim();
      if (!proj) {
        new Notice('Project name is required.');
        return;
      }
      const args = ['project-map', 'upsert', '--project', proj];
      if (pathsInput.value.trim()) args.push('--paths', pathsInput.value.trim());
      if (gitInput.value.trim()) args.push('--git-roots', gitInput.value.trim());
      if (slugInput.value.trim()) args.push('--slugs', slugInput.value.trim());
      const saveRes = await this.plugin.bridge.runJson(args);
      if (saveRes.ok) {
        new Notice(`Saved whitelist project "${proj}".`);
        this.editingEntry = null;
        await this.render();
      } else {
        new Notice(`Validation failed: ${saveRes.error}`);
      }
    });

    if (this.editingEntry) {
      const cancelBtn = btnRow.createEl('button', { text: 'Cancel' });
      cancelBtn.addEventListener('click', () => {
        this.editingEntry = null;
        void this.render();
      });
    }
  }

  private async renderBudgetTab(parent: HTMLElement): Promise<void> {
    const args = ['cloud-budget'];
    if (this.plugin.settings.operatorRoot) {
      args.push('--operator-root', this.plugin.settings.operatorRoot);
    }
    const res = await this.plugin.bridge.runJson<CloudBudgetResponse>(args);
    if (!res.ok || !res.data) {
      parent.createDiv({ cls: 'mindloom-card', text: `Failed to read cloud budget telemetry: ${res.error}` });
      return;
    }

    const data = res.data;
    const statusCard = parent.createDiv({ cls: 'mindloom-card' });
    const isoOk = data.operatorDbIsolation === 'admin_only_protected';
    statusCard.createSpan({
      cls: `mindloom-badge ${isoOk ? 'mindloom-badge-ok' : 'mindloom-badge-warn'}`,
      text: `Operator Isolation: ${data.operatorDbIsolation}`
    });
    statusCard.createDiv({
      cls: 'mindloom-muted',
      text: `Operator Root: ${data.operatorRoot} · Sanitized Egress Packages: ${data.egressPackagesCount}`
    });
    statusCard.createDiv({
      cls: 'mindloom-muted',
      text: 'Security Boundary: This plugin NEVER reads API key files or privileged operator databases, and NEVER bypasses human approval gates.'
    });

    const guideCard = parent.createDiv({ cls: 'mindloom-card' });
    guideCard.createEl('h4', { text: 'Privileged Cloud Actions (Administrator Terminal Only)' });
    const cmdBtns = guideCard.createDiv({ cls: 'mindloom-actions' });

    const showCmd = (title: string, desc: string, cmd: string) => {
      new AdminCommandModal(this.app, title, desc, cmd).open();
    };

    const btnSetup = cmdBtns.createEl('button', { text: 'Configure API Key / Isolation' });
    btnSetup.addEventListener('click', () =>
      showCmd(
        'Configure API Key & NTFS Operator Isolation',
        'Run in an elevated Administrator PowerShell terminal to configure API keys with Admin+SYSTEM-only NTFS ACLs.',
        data.adminCommands.setupIsolation
      )
    );

    const btnApprove = cmdBtns.createEl('button', { text: 'Issue CEGR-* Approval' });
    btnApprove.addEventListener('click', () =>
      showCmd(
        'Issue CEGR-* Cloud Egress Approval',
        'Run in an elevated interactive Administrator terminal to approve capped cloud usage.',
        data.adminCommands.issueCloudApproval
      )
    );

    const btnList = cmdBtns.createEl('button', { text: 'Inspect CEGR-* Ledger' });
    btnList.addEventListener('click', () =>
      showCmd(
        'Inspect Operator CEGR-* Budget Ledger',
        'Run in an Administrator terminal to inspect live operator approval balances.',
        data.adminCommands.listApprovals
      )
    );

    const btnDistill = cmdBtns.createEl('button', { text: 'Run Live Cloud Distill' });
    btnDistill.addEventListener('click', () =>
      showCmd(
        'Run Live Cloud Distill (Operator CLI)',
        'Replace <SES-ID> and <CEGR-...> and execute in an elevated Administrator terminal.',
        data.adminCommands.runDistill
      )
    );

    if (data.approvals && data.approvals.length > 0) {
      const approvalsCard = parent.createDiv({ cls: 'mindloom-card' });
      approvalsCard.createEl('h4', { text: `Exported CEGR-* Summary (${data.summaryUpdatedAt || 'snapshot'})` });
      for (const ap of data.approvals) {
        approvalsCard.createDiv({
          cls: 'mindloom-muted',
          text: `${String(ap.cloud_approval_id || '')} · ${String(ap.purpose || '')} · ${String(ap.model_id || '')} · status=${String(ap.status || '')} · calls=${String(ap.used_calls ?? 0)}/${String(ap.max_calls ?? 0)}`
        });
      }
    }

    const catalogCard = parent.createDiv({ cls: 'mindloom-card' });
    catalogCard.createEl('h4', { text: 'Built-in Provider Pricing Catalog' });
    for (const [provider, models] of Object.entries(data.pricingCatalog || {})) {
      for (const [modelId, pricing] of Object.entries(models)) {
        catalogCard.createDiv({
          cls: 'mindloom-muted',
          text: `${provider} / ${modelId}: ${String(pricing.inputMicroCnyPerMillionTokens ?? '?')} micro-CNY / 1M input tokens`
        });
      }
    }
  }
}
