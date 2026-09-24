<template>
  <div>
    <h1>Fail2ban</h1>
    <p>{{ $t("f.intro") }}</p>
    <p>{{ $t("f.discovery") }}</p>
    <p>{{ $t("f.constraints") }}</p>
    <p>
      <a
        href="https://github.com/Platypuschan/ns8-fail2ban-reworked"
        target="_blank"
        rel="noopener noreferrer"
        >{{ $t("f.documentation") }}</a
      >
    </p>
    <img
      :src="require('../assets/module_default_logo.png')"
      width="96"
      height="96"
      alt="Fail2ban"
    />
  </div>
</template>
<script>
export default { name: "About" };
</script>
<style scoped>
p,
h1 {
  margin-bottom: 1rem;
  max-width: 85ch;
  line-height: 1.5;
}
</style>
