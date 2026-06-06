import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import prettierConfig from 'eslint-config-prettier'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist', '**/*.min.js']),
  {
    files: ['**/*.ts'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      prettierConfig // added — must be last in extends
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.node,
      parserOptions: {
        // added — needed for type-aware lint rules. Uses a dedicated config
        // that includes test files (the build tsconfig excludes them).
        project: ['./tsconfig.eslint.json']
      }
    },
    rules: {
      // From @typescript-eslint recommended — already included, but be explicit:
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      // Always require curly braces
      curly: ['error', 'all'],

      // Prefer modern JS
      'no-var': 'error',
      'prefer-const': 'error'
    }
  }
])
