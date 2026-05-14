// Flat-config ESLint setup for Next.js 15. Mirrors the working
// pattern from VaporwareRMM-Edge so Vantage's lint stays consistent
// across the two products.
//
// Without this, `next lint` (which the package.json used to invoke)
// drops into an interactive configuration wizard that hangs CI.
// `next lint` itself is also deprecated in Next.js 15 and removed in
// 16, so the migration to the ESLint CLI is unavoidable.
//
// FlatCompat shim is used because eslint-config-next still ships as
// a legacy preset (`extends: ['next/core-web-vitals',
// 'next/typescript']`) and hasn't moved to native flat config yet.
// The shim disappears once Next ships a native flat-config export.

import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FlatCompat } from '@eslint/eslintrc'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const compat = new FlatCompat({
  baseDirectory: __dirname,
})

const eslintConfig = [
  ...compat.extends('next/core-web-vitals', 'next/typescript'),
  {
    // Build outputs + vendor. Without this ESLint scans .next/ and
    // public/ which can contain thousands of formatting errors in
    // generated bundles.
    ignores: [
      '.next/**',
      'out/**',
      'dist/**',
      'build/**',
      'node_modules/**',
      'public/**',
      'coverage/**',
      'tsconfig.tsbuildinfo',
      '**/*.tsbuildinfo',
      'next-env.d.ts',
    ],
  },
]

export default eslintConfig
