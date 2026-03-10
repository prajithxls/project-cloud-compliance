import React from "react";

export default function Topbar({ scanning, lastUpdated, user, onSignOut }) {
  return (
    <header className="topbar">
      <div className="topbar-title">
        Cloud Security Compliance and Audit Management System
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {scanning && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--accent-cyan)" }}>
            <div className="spinner" style={{ width: 12, height: 12 }} />
            SCANNING
          </div>
        )}
        {lastUpdated && !scanning && (
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
            Updated {lastUpdated.toLocaleTimeString()}
          </div>
        )}
        {user && (
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--text-secondary)",
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              padding: "4px 10px",
              maxWidth: 180,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}>
              {user.email}
            </div>
            <button
              onClick={onSignOut}
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                color: "var(--text-muted)",
                background: "transparent",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                padding: "4px 10px",
                cursor: "pointer",
                transition: "color 0.15s, border-color 0.15s",
              }}
              onMouseEnter={e => { e.target.style.color = "var(--critical)"; e.target.style.borderColor = "var(--critical)"; }}
              onMouseLeave={e => { e.target.style.color = "var(--text-muted)"; e.target.style.borderColor = "var(--border)"; }}
            >
              Sign Out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}