import names from './customerDisplayNames.json'

// Display aliases never replace customer identifiers in requests or signed evidence.
export function customerLabel(id: string): string {
  const alias = (names as Record<string, string>)[id]
  if (alias) return alias
  return id.length > 16 ? `客户-${id.replace(/^C-/, '').slice(0, 8).toUpperCase()}` : id
}
