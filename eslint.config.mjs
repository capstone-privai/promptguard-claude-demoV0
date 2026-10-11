import globals from 'globals'
export default [{ files: ['**/*.mjs'], languageOptions: { globals: { ...globals.node, ...globals.browser } }, rules: { 'no-console': 'error', 'no-eval': 'error', 'no-unused-vars': ['error', { caughtErrors: 'none', ignoreRestSiblings: true }], 'no-constant-condition': 'error' } }, { files: ['tests/**/*.mjs'], rules: { 'no-console': 'off' } }]
