<template>
  <div class="page">
    <h1>{{ $t("status.title") }}</h1>
    <p>{{ $t("f.diagnosticsHelp") }}</p>
    <cv-button :disabled="loading" @click="refresh">{{
      $t("f.refresh")
    }}</cv-button>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('f.error')"
      :sub-title="error"
    />
    <template v-if="status">
      <dl>
        <dt>{{ $t("f.revision") }}</dt>
        <dd>{{ status.revision }}</dd>
        <dt>{{ $t("f.pendingBans") }}</dt>
        <dd>{{ status.pending_bans }}</dd>
        <dt>{{ $t("f.pendingNotifications") }}</dt>
        <dd>{{ status.pending_notifications }}</dd>
      </dl>
      <table class="bx--data-table">
        <thead>
          <tr>
            <th>{{ $t("f.component") }}</th>
            <th>{{ $t("f.state") }}</th>
            <th>{{ $t("f.details") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="key in checks" :key="key">
            <td>{{ $t("f." + key) }}</td>
            <td>
              {{
                status[key].ok === true
                  ? $t("f.ready")
                  : status[key].ok === false
                  ? $t("f.attention")
                  : "—"
              }}
            </td>
            <td>
              {{
                status[key].error ||
                status[key].last_success ||
                status[key].updated ||
                "—"
              }}
            </td>
          </tr>
          <tr v-for="(state, service) in status.services" :key="service">
            <td>{{ service }}</td>
            <td>{{ state }}</td>
            <td></td>
          </tr>
        </tbody>
      </table>
    </template>
  </div>
</template>
<script>
import task from "../task";
export default {
  name: "Status",
  mixins: [task],
  data: () => ({
    loading: false,
    error: "",
    status: null,
    checks: [
      "sync_status",
      "firewall_status",
      "engine_status",
      "collector_status",
      "notification_status",
    ],
  }),
  created() {
    this.refresh();
  },
  methods: {
    async refresh() {
      this.loading = true;
      this.error = "";
      try {
        this.status = await this.task("get-diagnostics");
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>
<style scoped>
.page {
  max-width: 1050px;
}
h1,
p {
  margin-bottom: 1rem;
}
dl {
  margin: 2rem 0;
  display: grid;
  grid-template-columns: 20rem 1fr;
  gap: 0.6rem;
}
</style>
