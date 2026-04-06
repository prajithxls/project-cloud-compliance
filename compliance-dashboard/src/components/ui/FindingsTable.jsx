import React, { useState } from "react";
import { getRiskClass, formatDateTime } from "../../utils/helpers";

const COLUMNS = [
  { key: "findingId",    label: "Finding ID",    sortable: true  },
  { key: "accountId",   label: "Account ID",    sortable: true  },
  { key: "scanner",     label: "Scanner",       sortable: true  },
  { key: "resourceType",label: "Resource Type", sortable: true  },
  { key: "resourceId",  label: "Resource ID",   sortable: false },
  { key: "severity",    label: "Severity",      sortable: true  },
  { key: "riskScore",   label: "Risk",          sortable: true  },
  { key: "title",       label: "Title",         sortable: true  },
  { key: "status",      label: "Status",        sortable: true  },
  { key: "timestamp",   label: "Timestamp",     sortable: true  },
];

export default function FindingsTable({ findings, sortKey, sortDir, onSort, loading }) {
  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="spinner" />
        <div className="loading-text">LOADING FINDINGS...</div>
      </div>
    );
  }

  if (!findings.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚑</div>
        <div className="empty-state-title">No findings match your filters</div>
        <div className="empty-state-sub">Try adjusting your search query or filters</div>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className={sortKey === col.key ? "sorted" : ""}
                onClick={col.sortable ? () => onSort(col.key) : undefined}
                style={{ cursor: col.sortable ? "pointer" : "default" }}
              >
                {col.label}
                {col.sortable && (
                  <span className="sort-indicator">
                    {sortKey === col.key ? (sortDir === "asc" ? " ↑" : " ↓") : " ↕"}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <FindingRow key={f.findingId} finding={f} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* Truncated by default, expands on hover, click copies */
function TruncatedCell({ value, maxChars = 12, mono = true, dim = false }) {
  const [hovered, setHovered] = useState(false);
  const [copied, setCopied] = useState(false);

  const isLong = value && value.length > maxChars;
  const display = isLong && !hovered
    ? value.slice(0, maxChars) + "…"
    : value;

  const handleClick = () => {
    if (!value) return;
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { setHovered(false); setCopied(false); }}
      onClick={handleClick}
      title={isLong ? value : undefined}
      style={{
        fontFamily: mono ? "var(--font-mono)" : "inherit",
        fontSize: 11,
        color: copied
          ? "var(--low)"
          : hovered
          ? "var(--text-primary)"
          : dim ? "var(--text-muted)" : "var(--text-secondary)",
        cursor: isLong ? "pointer" : "default",
        whiteSpace: hovered ? "normal" : "nowrap",
        wordBreak: hovered ? "break-all" : "normal",
        lineHeight: 1.5,
        transition: "color 0.15s",
        maxWidth: hovered ? 320 : "none",
        background: hovered && isLong ? "var(--bg-elevated)" : "transparent",
        padding: hovered && isLong ? "4px 6px" : "0",
        borderRadius: hovered && isLong ? "4px" : "0",
        zIndex: hovered ? 10 : "auto",
        position: "relative",
      }}
    >
      {copied ? "✓ copied!" : display}
    </div>
  );
}

function FindingRow({ finding: f }) {
  return (
    <tr>
      {/* Finding ID */}
      <td style={{ maxWidth: 120 }}>
        <TruncatedCell value={f.findingId || "—"} maxChars={8} dim />
      </td>

      {/* Account ID */}
      <td>
        <TruncatedCell value={f.accountId || "—"} maxChars={14} />
      </td>

      {/* Scanner */}
      <td>
        <span style={{
          padding: "2px 8px",
          background: "var(--accent-cyan-dim)",
          color: "var(--accent-cyan)",
          borderRadius: "var(--radius-sm)",
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          fontWeight: 700,
          whiteSpace: "nowrap",
        }}>
          {f.scanner || "—"}
        </span>
      </td>

      {/* Resource Type */}
      <td className="primary" style={{ whiteSpace: "nowrap" }}>
        {f.resourceType || "—"}
      </td>

      {/* Resource ID */}
      <td style={{ maxWidth: 160 }}>
        <TruncatedCell value={f.resourceId || "—"} maxChars={22} />
      </td>

      {/* Severity */}
      <td>
        <span className={`badge ${f.severity?.toUpperCase()}`}>
          {f.severity || "—"}
        </span>
      </td>

      {/* Risk Score */}
      <td>
        <span className={`risk-score ${getRiskClass(f.riskScore)}`}>
          {parseFloat(f.riskScore).toFixed(1) || "—"}
        </span>
      </td>

      {/* Title — truncated, expands on hover */}
      <td style={{ color: "var(--text-primary)", maxWidth: 300 }}>
        <TruncatedCell value={f.title || "—"} maxChars={35} mono={false} />
      </td>

      {/* Status */}
      <td>
        <span className={`badge ${f.status?.toUpperCase()}`}>
          {f.status || "—"}
        </span>
      </td>

      {/* Timestamp */}
      <td className="mono" style={{ fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
        {formatDateTime(f.timestamp)}
      </td>
    </tr>
  );
}