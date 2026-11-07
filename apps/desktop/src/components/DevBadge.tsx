/** ADR-0028: Mooring Dev keeps its own identifier and data; the badge says so wherever the name shows. */
export function DevBadge() {
  return <span className="dev-badge" title="Mooring Dev: development build with its own data">Dev</span>;
}
