import React from "react";
import { timeAgo } from "../../utils/helpers";

export default function Topbar({ scanning, lastUpdated }) {
  return (
    <header className="topbar">
      <div style={{ display: "flex", alignItems: "center", flex: 1 }}>
        <div style={{
          fontFamily: "var(--font-display)",
          fontWeight: 800,
          fontSize: 16,
          color: "var(--text-primary)",
          letterSpacing: "-0.3px",
          whiteSpace: "nowrap",
        }}>
          Cloud Security Compliance and Audit Management System
        </div>
      </div>

      <div className="topbar-status">
        <div className={`status-dot ${scanning ? "scanning" : ""}`} />
        {scanning
          ? "SCANNING..."
          : lastUpdated
          ? `LAST SYNC ${timeAgo(lastUpdated).toUpperCase()}`
          : "READY"}
      </div>
    </header>
  );
}