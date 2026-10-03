module.exports = {
  root: true,
  env: {
    browser: true,
    node: true,
  },
  extends: ["plugin:vue/essential", "eslint:recommended", "@vue/prettier"],
  parserOptions: {
    parser: "@babel/eslint-parser",
    requireConfigFile: false,
  },
  rules: {
    "no-console": "off",
    "no-debugger": process.env.NODE_ENV === "production" ? "warn" : "off",
  },
};
