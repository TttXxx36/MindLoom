import { App, Notice, PluginSettingTab, Setting } from 'obsidian';
import type MindLoomPlugin from './main';

export class MindLoomSettingTab extends PluginSettingTab {
  private plugin: MindLoomPlugin;

  constructor(app: App, plugin: MindLoomPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl('h2', { text: 'MindLoom Companion Console Settings' });
    containerEl.createEl('p', {
      cls: 'mindloom-muted',
      text: 'All database and file operations execute via the isolated Node >= 22 CLI. This plugin never reads API keys or privileged operator databases directly.'
    });

    new Setting(containerEl)
      .setName('Vault Path Override')
      .setDesc('Leave empty to auto-detect the current Obsidian Vault path.')
      .addText((t) =>
        t
          .setPlaceholder('Auto-detected from Obsidian Vault')
          .setValue(this.plugin.settings.vaultPath)
          .onChange(async (val) => {
            this.plugin.settings.vaultPath = val.trim();
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Data Directory Path')
      .setDesc('Isolated MindLoom-Data directory containing runtime/state.sqlite and manifests/.')
      .addText((t) =>
        t
          .setPlaceholder('e.g. ~/Documents/Obsidian/MindLoom-Data')
          .setValue(this.plugin.settings.dataPath)
          .onChange(async (val) => {
            this.plugin.settings.dataPath = val.trim();
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Node.js (>= 22) Executable')
      .setDesc('Leave empty to auto-locate system node.')
      .addText((t) =>
        t
          .setPlaceholder('node')
          .setValue(this.plugin.settings.nodePath)
          .onChange(async (val) => {
            this.plugin.settings.nodePath = val.trim();
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('CLI Entrypoint (mem.mjs)')
      .setDesc('Leave empty to use <DataDir>/cli/mem.mjs.')
      .addText((t) =>
        t
          .setPlaceholder('<DataDir>/cli/mem.mjs')
          .setValue(this.plugin.settings.cliPath)
          .onChange(async (val) => {
            this.plugin.settings.cliPath = val.trim();
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Operator Isolation Root (Display Only)')
      .setDesc('Used only to format copy-ready Admin terminal commands.')
      .addText((t) =>
        t
          .setPlaceholder('C:\\ProgramData\\MindLoom or ~/.mindloom-operator')
          .setValue(this.plugin.settings.operatorRoot)
          .onChange(async (val) => {
            this.plugin.settings.operatorRoot = val.trim();
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('CLI Timeout (ms)')
      .addText((t) =>
        t
          .setValue(String(this.plugin.settings.timeoutMs))
          .onChange(async (val) => {
            const num = Number.parseInt(val, 10);
            if (Number.isFinite(num) && num >= 1000) {
              this.plugin.settings.timeoutMs = num;
              await this.plugin.saveSettings();
            }
          })
      );

    new Setting(containerEl)
      .setName('Verify CLI Connection')
      .setDesc('Runs "mem doctor --json" via CliBridge.')
      .addButton((btn) =>
        btn
          .setButtonText('Run mem doctor')
          .setCta()
          .onClick(async () => {
            const res = await this.plugin.bridge.runJson<{ ok?: boolean; nodeVersion?: string; dbStatus?: string }>(['doctor']);
            if (res.ok && res.data) {
              new Notice(`MindLoom Doctor OK=${String(res.data.ok)} (Node ${res.data.nodeVersion}, DB=${res.data.dbStatus})`);
            } else {
              new Notice(`Doctor failed: ${res.error || 'unknown error'}`);
            }
          })
      );
  }
}
