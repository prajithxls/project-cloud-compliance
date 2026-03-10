import React, { useState } from "react";

const SCANNERS = [
  {
    id: "s3",
    icon: "◧",
    label: "S3 Scanner",
    desc: "Evaluates S3 bucket policies, ACLs, and public access block configurations.",
    checks: ["Public access block", "Bucket ACLs", "Encryption settings"],
    color: "var(--high)",
  },
  {
    id: "ec2",
    icon: "⬡",
    label: "EC2 Scanner",
    desc: "Audits EC2 security groups for overly permissive inbound rules.",
    checks: ["Inbound 0.0.0.0/0 rules", "Port exposure", "Security group hygiene"],
    color: "var(--accent-cyan)",
  },
  {
    id: "iam",
    icon: "◉",
    label: "IAM Scanner",
    desc: "Checks IAM users and roles for missing MFA and over-privileged policies.",
    checks: ["MFA enforcement", "Access key rotation", "Role policy review"],
    color: "var(--info)",
  },
  {
    id: "lambda",
    icon: "λ",
    label: "Lambda Scanner",
    desc: "Audits Lambda functions for deprecated runtimes, overly permissive roles, and missing encryption.",
    checks: ["Deprecated runtimes", "Overpermissive execution roles", "Unencrypted environment variables"],
    color: "var(--medium)",
  },
];

export default function ScanPage({ scanning, scanLog, onScan, findingsCount }) {
  const [accountId, setAccountId] = useState("");

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Scan</div>
          <div className="page-title-sub">
            Trigger AWS resource audits across S3, EC2, IAM and Lambda
          </div>
        </div>
        <button
          className="btn btn-primary"
          style={{ fontSize: 14, padding: "10px 28px" }}
          onClick={onScan}
          disabled={scanning}
        >
          {scanning ? (
            <><div className="spinner dark" /> Scanning...</>
          ) : (
            <>⟳ Run Compliance Scan</>
          )}
        </button>
      </div>

      {/* Cross-Account Card — In Development */}
      <div className="card" style={{ marginBottom: 16, border: "1px solid #1e3a2f", position: "relative", overflow: "hidden" }}>
        <div className="card-header">
          <span className="card-title" style={{ color: "var(--text-secondary)" }}>
            🔗 Cross-Account Scanning
          </span>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            fontWeight: 700,
            color: "#00c87a",
            background: "#0d2d1e",
            border: "1px solid #00c87a55",
            padding: "3px 10px",
            borderRadius: "20px",
            letterSpacing: "0.08em",
          }}>
            ⚙ IN DEVELOPMENT
          </span>
        </div>

        <p style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 14 }}>
          Scan external AWS accounts by providing a target Account ID. The target account must have
          a <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--accent-cyan)" }}>CrossAccountComplianceRole</span> configured
          with a trust policy pointing to this account.
        </p>

        <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap", opacity: 0.45, pointerEvents: "none" }}>
          <div style={{ flex: 1, minWidth: 260 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 6, letterSpacing: "0.08em" }}>
              TARGET AWS ACCOUNT ID
            </div>
            <input
              type="text"
              placeholder="e.g. 123456789012"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              maxLength={12}
              disabled
              style={{
                width: "100%",
                padding: "10px 14px",
                background: "var(--bg-base)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
                fontSize: 15,
                letterSpacing: "0.1em",
                cursor: "not-allowed",
              }}
            />
          </div>
          <button
            className="btn btn-secondary"
            disabled
            style={{ fontSize: 14, padding: "10px 24px", flexShrink: 0, cursor: "not-allowed" }}
          >
            ⟳ Scan Target Account
          </button>
        </div>

        <div style={{ marginTop: 14, display: "flex", gap: 20, flexWrap: "wrap" }}>
          {["STS AssumeRole integration", "Cross-account IAM trust policy", "Multi-account findings dashboard"].map(f => (
            <div key={f} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-muted)" }}>
              <span style={{ color: "#00c87a55", fontSize: 10 }}>◎</span> {f}
            </div>
          ))}
        </div>
      </div>

      {/* Scan Log */}
      {scanLog.length > 0 && (
        <div className="scan-log">
          {scanLog.map((entry, i) => (
            <div key={i} className="scan-log-entry">
              <span className="time">[{entry.time}]</span>
              <span className={entry.type}>{entry.msg}</span>
            </div>
          ))}
        </div>
      )}

      {/* Scanner Cards */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
        gap: 16,
        marginTop: 24,
      }}>
        {SCANNERS.map((scanner) => (
          <div key={scanner.id} className="card" style={{ borderTop: `2px solid ${scanner.color}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <div style={{
                width: 44, height: 44,
                background: `${scanner.color}18`,
                border: `1px solid ${scanner.color}33`,
                borderRadius: "var(--radius-md)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 22, color: scanner.color,
              }}>
                {scanner.icon}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: 15, color: "var(--text-primary)" }}>
                  {scanner.label}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: scanner.color, letterSpacing: "0.06em" }}>
                  ACTIVE
                </div>
              </div>
            </div>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 14 }}>
              {scanner.desc}
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {scanner.checks.map((check) => (
                <div key={check} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
                  <span style={{ color: "var(--low)", fontSize: 10 }}>✓</span>
                  <span style={{ color: "var(--text-secondary)" }}>{check}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Current State */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <span className="card-title">Current State</span>
        </div>
        <div style={{ display: "flex", gap: 40, flexWrap: "wrap" }}>
          {[
            { label: "Total Findings in DB", value: findingsCount,   color: "var(--accent-cyan)"    },
            { label: "Scan Region",          value: "ap-south-1",    color: "var(--text-secondary)" },
            { label: "Scanners Active",      value: "4",             color: "var(--low)"            },
            { label: "Storage",              value: "DynamoDB + S3", color: "var(--low)"            },
          ].map((item) => (
            <div key={item.label}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.08em", marginBottom: 4 }}>
                {item.label.toUpperCase()}
              </div>
              <div style={{ fontFamily: "var(--font-display)", fontSize: 18, fontWeight: 700, color: item.color }}>
                {item.value}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}