<template>
  <div class="page">
    <h1>{{ $t("settings.title") }}</h1>
    <p class="intro">{{ $t("f.intro") }}</p>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('f.error')"
      :sub-title="error"
      @close="error = ''"
    />
    <cv-inline-notification
      v-if="success"
      kind="success"
      :title="success"
      @close="success = ''"
    />
    <cv-loading v-if="loading" :active="true" />
    <template v-if="loaded">
      <section>
        <h2>{{ $t("f.protection") }}</h2>
        <p>{{ $t("f.discovery") }}</p>
        <p>{{ $t("f.threshold") }}</p>
        <ul class="sources">
          <li v-for="source in sources" :key="source.module + source.jail">
            <strong>{{ source.jail }}</strong> · {{ source.module }} —
            {{ source.ready ? $t("f.ready") : $t("f.attention") }}
            <span v-if="source.error">: {{ source.error }}</span>
          </li>
        </ul>
        <p v-if="!sources.length">{{ $t("f.afterSetup") }}</p>
      </section>
      <section>
        <h2>{{ $t("f.synchronization") }}</h2>
        <p>{{ $t("f.shared") }}</p>
        <cv-select
          v-model="form.mode"
          :label="$t('f.mode')"
          :disabled="configured || busy"
        >
          <cv-select-option value="coordinator">{{
            $t("f.coordinator")
          }}</cv-select-option>
          <cv-select-option value="peer">{{ $t("f.peer") }}</cv-select-option>
        </cv-select>
        <template v-if="form.mode === 'coordinator'">
          <h3>{{ $t("f.database") }}</h3>
          <p>{{ $t("f.databaseHelp") }}</p>
          <cv-text-input
            v-model="form.public_url"
            :label="$t('f.publicUrl')"
            placeholder="https://bans.example.org"
            :helper-text="$t('f.proxyHelp')"
          />
          <div v-if="configured" class="token">
            <cv-button
              kind="secondary"
              size="small"
              :disabled="busy"
              @click="showToken"
              >{{ $t("f.showToken") }}</cv-button
            >
            <cv-text-input
              v-if="connectionToken"
              :value="connectionToken"
              :label="$t('f.syncToken')"
              readonly
            />
          </div>
        </template>
        <template v-else>
          <cv-text-input
            v-model="form.sync_url"
            :label="$t('f.coordinatorUrl')"
            placeholder="https://bans.example.org"
          />
          <cv-text-input
            v-model="form.sync_token"
            type="password"
            :label="$t('f.syncToken')"
            :helper-text="configured ? $t('f.keepSecret') : ''"
            autocomplete="new-password"
          />
        </template>
      </section>
      <section>
        <h2>{{ $t("f.notifications") }}</h2>
        <p>{{ $t("f.notifyHelp") }}</p>
        <cv-toggle
          v-model="form.notifications.enabled"
          :label="$t('f.enableNotifications')"
        >
          <template slot="text-left">{{ $t("f.disabled") }}</template>
          <template slot="text-right">{{ $t("f.enabled") }}</template>
        </cv-toggle>
        <div v-if="form.notifications.enabled" class="notification-fields">
          <cv-text-input
            v-model="form.notifications.url"
            :label="$t('f.serverUrl')"
            placeholder="https://ntfy.example.org"
          />
          <cv-text-input
            v-model="form.notifications.topic"
            :label="$t('f.topic')"
          />
          <cv-text-input
            v-model="form.notifications.token"
            type="password"
            :label="$t('f.token')"
            :helper-text="$t('f.keepSecret')"
            autocomplete="new-password"
          />
          <cv-checkbox
            v-if="ntfyTokenConfigured"
            v-model="form.notifications.clear_token"
            value="clear"
            :label="$t('f.clearToken')"
          />
        </div>
      </section>
      <cv-button :disabled="busy" @click="save">{{
        $t("f.saveSettings")
      }}</cv-button>
      <section>
        <h2>{{ $t("f.whitelist") }}</h2>
        <p>{{ $t("f.whitelistHelp") }}</p>
        <cv-text-area
          v-model="whitelist"
          :label="$t('f.ranges')"
          :rows="5"
          placeholder="192.168.178.0/24&#10;2001:db8::/32"
        />
        <cv-button
          kind="secondary"
          :disabled="busy || !configured"
          @click="saveWhitelist"
          >{{ $t("f.saveWhitelist") }}</cv-button
        >
      </section>
      <section>
        <h2>{{ $t("f.blocked") }} ({{ bans.length }})</h2>
        <div class="toolbar">
          <cv-button
            kind="danger"
            size="small"
            :disabled="busy || !selected.length"
            @click="unban"
            >{{ $t("f.unban") }} ({{ selected.length }})</cv-button
          >
          <cv-button
            kind="ghost"
            size="small"
            :disabled="busy"
            @click="refreshBans"
            >{{ $t("f.refresh") }}</cv-button
          >
          <cv-text-input v-model="search" :label="$t('f.search')" />
        </div>
        <div class="table-scroll">
          <table class="bx--data-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    :aria-label="$t('f.selectAll')"
                    :checked="allSelected"
                    @change="selectAll($event.target.checked)"
                  />
                </th>
                <th>IP</th>
                <th>{{ $t("f.since") }}</th>
                <th>Jail</th>
                <th>{{ $t("f.detectedBy") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ban in visibleBans" :key="ban.ip">
                <td>
                  <input
                    v-model="selected"
                    type="checkbox"
                    :value="ban.ip"
                    :aria-label="ban.ip"
                  />
                </td>
                <td>
                  <code>{{ ban.ip }}</code>
                </td>
                <td>{{ formatDate(ban.since) }}</td>
                <td>{{ ban.jail }}</td>
                <td>{{ ban.node }}<br />{{ ban.module }}</td>
              </tr>
              <tr v-if="!visibleBans.length">
                <td colspan="5">{{ $t("f.noBans") }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </div>
</template>

<script>
import task from "../task";
export default {
  name: "Settings",
  mixins: [task],
  data: () => ({
    loading: false,
    loaded: false,
    busy: false,
    error: "",
    success: "",
    configured: false,
    form: {
      mode: "coordinator",
      public_url: "",
      sync_url: "",
      sync_token: "",
      notifications: {
        enabled: false,
        url: "",
        topic: "",
        token: "",
        clear_token: false,
      },
    },
    connectionToken: "",
    ntfyTokenConfigured: false,
    whitelist: "",
    whitelistRevision: 0,
    bans: [],
    sources: [],
    selected: [],
    search: "",
  }),
  computed: {
    visibleBans() {
      return this.bans.filter((b) => b.ip.includes(this.search.trim()));
    },
    allSelected() {
      return (
        this.visibleBans.length > 0 &&
        this.visibleBans.every((b) => this.selected.includes(b.ip))
      );
    },
  },
  async created() {
    this.loading = true;
    await this.perform(async () => this.load());
    this.loading = false;
    this.timer = setInterval(() => {
      if (!this.busy && this.configured) this.refreshBans();
    }, 15000);
  },
  beforeDestroy() {
    clearInterval(this.timer);
    this.connectionToken = "";
  },
  methods: {
    async perform(operation) {
      this.busy = true;
      this.error = "";
      try {
        await operation();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    async load() {
      const result = await this.task("get-configuration");
      this.configured = result.configured;
      this.form = {
        mode: result.mode,
        public_url: result.public_url,
        sync_url: result.sync_url,
        sync_token: "",
        notifications: {
          ...result.notifications,
          token: "",
          clear_token: false,
        },
      };
      this.ntfyTokenConfigured = result.notifications.token_configured;
      this.whitelist = result.whitelist.join("\n");
      this.whitelistRevision = result.whitelist_revision;
      this.bans = result.bans;
      this.sources = result.sources;
      this.loaded = true;
      this.selected = this.selected.filter((ip) =>
        this.bans.some((b) => b.ip === ip)
      );
    },
    save() {
      return this.perform(async () => {
        await this.task("configure-module", this.form);
        await this.load();
        this.success = this.$t("f.saved");
      });
    },
    showToken() {
      return this.perform(async () => {
        this.connectionToken = (
          await this.task("get-connection-token")
        ).sync_token;
      });
    },
    saveWhitelist() {
      return this.perform(async () => {
        await this.task("set-whitelist", {
          whitelist: this.whitelist
            .split(/\n/)
            .map((x) => x.trim())
            .filter(Boolean),
          revision: this.whitelistRevision,
        });
        const result = await this.task("get-configuration");
        this.whitelist = result.whitelist.join("\n");
        this.whitelistRevision = result.whitelist_revision;
        this.bans = result.bans;
        this.success = this.$t("f.saved");
      });
    },
    unban() {
      return this.perform(async () => {
        await this.task("unban-addresses", { ips: this.selected });
        this.selected = [];
        await this.fetchBans();
        this.success = this.$t("f.unbanned");
      });
    },
    async fetchBans() {
      const result = await this.task("get-configuration");
      this.bans = result.bans;
      this.sources = result.sources;
    },
    refreshBans() {
      return this.perform(() => this.fetchBans());
    },
    selectAll(value) {
      this.selected = value
        ? this.visibleBans.slice(0, 1000).map((b) => b.ip)
        : [];
    },
    formatDate(value) {
      return value ? new Date(value).toLocaleString() : "";
    },
  },
};
</script>

<style scoped>
.page {
  max-width: 1050px;
  padding-bottom: 3rem;
}
h1 {
  margin-bottom: 1rem;
}
h2 {
  margin-bottom: 1rem;
}
h3 {
  margin: 1.5rem 0 0.75rem;
}
p {
  margin-bottom: 1rem;
  max-width: 85ch;
  line-height: 1.5;
}
section {
  margin: 2rem 0;
  padding-top: 1rem;
  border-top: 1px solid #c6c6c6;
}
.bx--form-item {
  margin-bottom: 1rem;
}
.sources li {
  margin: 0.6rem 0;
}
.toolbar {
  display: flex;
  align-items: end;
  gap: 1rem;
  margin: 1rem 0;
  flex-wrap: wrap;
}
.table-scroll {
  overflow-x: auto;
}
.token,
.notification-fields {
  margin-top: 1rem;
}
input[type="checkbox"] {
  width: 1.1rem;
  height: 1.1rem;
  cursor: pointer;
}
</style>
