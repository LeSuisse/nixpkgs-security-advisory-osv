import eslint from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from "eslint-config-prettier"
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended"

export default defineConfig(
  globalIgnores(["advisories/*"]),
  {
  extends: [
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    eslintConfigPrettier,
    eslintPluginPrettierRecommended
  ],
  languageOptions: {
    parserOptions: {
      project: "./tsconfig.json",
    },
  },
  rules: {
    "@typescript-eslint/consistent-type-imports": "error"
  },
});
