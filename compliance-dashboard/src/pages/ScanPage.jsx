import React, { useState } from "react";

const SCANNERS = [
  {
    id: "s3", icon: "◧", label: "S3 Scanner",
    desc: "Evaluates S3 bucket policies, ACLs, and public access block configurations.",
    checks: ["Public access block", "Bucket ACLs", "Encryption settings"],
    color: "var(--high)",
  },
  {
    id: "ec2", icon: "⬡", label: "EC2 Scanner",
    desc: "Audits EC2 security groups for overly permissive inbound rules.",
    checks: ["Inbound 0.0.0.0/0 rules", "Port exposure", "Security group hygiene"],
    color: "var(--accent-cyan)",
  },
  {
    id: "iam", icon: "◉", label: "IAM Scanner",
    desc: "Checks IAM users and roles for missing MFA and over-privileged policies.",
    checks: ["MFA enforcement", "Access key rotation", "Role policy review"],
    color: "var(--info)",
  },
  {
    id: "lambda", icon: "λ", label: "Lambda Scanner",
    desc: "Audits Lambda functions for deprecated runtimes, overly permissive roles, and missing encryption.",
    checks: ["Deprecated runtimes", "Overpermissive execution roles", "Unencrypted environment variables"],
    color: "var(--medium)",
  },
];

const SETUP_STEPS = [
  {
    number: "01",
    title: "Sign in to the target AWS account",
    detail: "Log in to the AWS Management Console of the account you want to scan. You will need administrator access to create IAM roles.",
  },
  {
    number: "02",
    title: "Open the IAM console",
    detail: "Navigate to the IAM (Identity and Access Management) service. In the left sidebar, click on Roles, then click the Create role button.",
  },
  {
    number: "03",
    title: "Set up a trusted entity",
    detail: "Select AWS account as the trusted entity type. Choose Another AWS account and enter the 12-digit Account ID of the account where this scanner is hosted.",
  },
  {
    number: "04",
    title: "Attach the SecurityAudit policy",
    detail: "On the permissions step, search for and attach the AWS managed policy named SecurityAudit. This is a read-only policy that allows inspection of resource configurations — it cannot modify or delete anything.",
  },
  {
    number: "05",
    title: "Name the role exactly as shown",
    detail: "On the final step, set the role name to CrossAccountComplianceRole. This exact name is required — the scanner will look for this role when assuming access to the target account.",
  },
  {
    number: "06",
    title: "Save the role and enter the account ID below",
    detail: "Once the role is created, come back here and enter the 12-digit Account ID of the target account. The scanner will assume the role automatically and begin auditing.",
  },
];

export default function ScanPage({ scanning, scanLog, onScan, findingsCount, scannedAccountId }) {
  const [accountId,      setAccountId]      = useState("");
  const [accountIdError, setAccountIdError] = useState("");
  const [setupOpen,      setSetupOpen]      = useState(false);

  const handleScan = () => {
    const trimmed = accountId.trim();
    if (!trimmed) { setAccountIdError("Account ID is required"); return; }
    if (!/^\d{12}$/.test(trimmed)) { setAccountIdError("Account ID must be exactly 12 digits"); return; }
    setAccountIdError("");
    onScan(trimmed);
  };

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
        {scannedAccountId && (
          <div style={{
            fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--low)",
            background: "var(--bg-elevated)", border: "1px solid var(--low)44",
            padding: "6px 14px", borderRadius: "20px",
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <span style={{ color: "var(--low)" }}>✓</span>
            Last scanned: <span style={{ color: "var(--accent-cyan)" }}>{scannedAccountId}</span>
          </div>
        )}
      </div>

      {/* Cross-Account Scan Card */}
      <div className="card" style={{ marginBottom: 16, border: "1px solid #1a3a5c" }}>
        <div className="card-header">
          <span className="card-title">Cross-Account Scanning</span>
        </div>

        <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 20 }}>
          Enter the 12-digit Account ID of the AWS account you want to audit. The scanner will securely
          assume a read-only role in that account via AWS STS and run compliance checks across
          S3, EC2, IAM, and Lambda — without requiring any credentials from you.
        </p>

        {/* Account ID input */}
        <div style={{ display: "flex", gap: 12, alignItems: "flex-start", flexWrap: "wrap", marginBottom: 20 }}>
          <div style={{ flex: 1, minWidth: 260 }}>
            <div style={{
              fontFamily: "var(--font-mono)", fontSize: 10,
              color: "var(--text-muted)", marginBottom: 6, letterSpacing: "0.08em",
            }}>
              TARGET AWS ACCOUNT ID
            </div>
            <input
              type="text"
              placeholder="e.g. 123456789012"
              value={accountId}
              onChange={(e) => { setAccountId(e.target.value.replace(/\D/g, "")); setAccountIdError(""); }}
              maxLength={12}
              disabled={scanning}
              style={{
                width: "100%", padding: "10px 14px",
                background: "var(--bg-base)",
                border: `1px solid ${accountIdError ? "var(--critical)" : "var(--border)"}`,
                borderRadius: "var(--radius-md)",
                color: "var(--text-primary)", fontFamily: "var(--font-mono)",
                fontSize: 15, letterSpacing: "0.1em", outline: "none",
                transition: "border-color 0.15s", boxSizing: "border-box",
              }}
              onFocus={(e) => e.target.style.borderColor = "var(--accent-cyan)"}
              onBlur={(e) => e.target.style.borderColor = accountIdError ? "var(--critical)" : "var(--border)"}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            {accountIdError && (
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--critical)", marginTop: 6 }}>
                ⚠ {accountIdError}
              </div>
            )}
            {accountId.length > 0 && !accountIdError && (
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                {accountId.length}/12 digits
                {accountId.length === 12 && (
                  <span style={{ color: "var(--low)", marginLeft: 8 }}>✓ Valid format</span>
                )}
              </div>
            )}
          </div>
          <button
            className="btn btn-primary"
            style={{ fontSize: 14, padding: "10px 28px", flexShrink: 0, marginTop: 20 }}
            onClick={handleScan}
            disabled={scanning || accountId.length !== 12}
          >
            {scanning ? <><div className="spinner dark" /> Scanning...</> : <>⟳ Scan Target Account</>}
          </button>
        </div>

        <div style={{ display: "flex", gap: 20, flexWrap: "wrap", marginBottom: 20 }}>
          {["STS AssumeRole integration", "Read-only SecurityAudit policy", "Findings isolated per account ID", "No credentials stored"].map(f => (
            <div key={f} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
              <span style={{ color: "var(--low)", fontSize: 10 }}>✓</span> {f}
            </div>
          ))}
        </div>

        {/* Setup instructions — collapsible */}
        <div style={{
          borderTop: "1px solid var(--border)",
          paddingTop: 16,
        }}>
          <button
            className="btn btn-ghost"
            style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 8, padding: "6px 0" }}
            onClick={() => setSetupOpen(o => !o)}
          >
            <span style={{
              display: "inline-block",
              transform: setupOpen ? "rotate(90deg)" : "rotate(0deg)",
              transition: "transform 0.2s",
              fontSize: 10,
            }}>▶</span>
            How to set up the target account — step by step guide
          </button>

          {setupOpen && (
            <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 0 }}>
              {SETUP_STEPS.map((step, i) => (
                <div
                  key={step.number}
                  style={{
                    display: "flex",
                    gap: 16,
                    paddingBottom: i < SETUP_STEPS.length - 1 ? 20 : 0,
                    position: "relative",
                  }}
                >
                  {/* Vertical connector line */}
                  {i < SETUP_STEPS.length - 1 && (
                    <div style={{
                      position: "absolute",
                      left: 19,
                      top: 38,
                      bottom: 0,
                      width: 1,
                      background: "var(--border)",
                    }} />
                  )}

                  {/* Step number circle */}
                  <div style={{
                    flexShrink: 0,
                    width: 38, height: 38,
                    borderRadius: "50%",
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--accent-cyan)44",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontFamily: "var(--font-mono)",
                    fontSize: 11,
                    fontWeight: 700,
                    color: "var(--accent-cyan)",
                    zIndex: 1,
                  }}>
                    {step.number}
                  </div>

                  <div style={{ paddingTop: 8 }}>
                    <div style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      marginBottom: 4,
                    }}>
                      {step.title}
                    </div>
                    <div style={{
                      fontSize: 12,
                      color: "var(--text-secondary)",
                      lineHeight: 1.65,
                    }}>
                      {step.detail}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
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
        gap: 16, marginTop: 24,
      }}>
        {SCANNERS.map((scanner) => (
          <div key={scanner.id} className="card" style={{ borderTop: `2px solid ${scanner.color}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <div style={{
                width: 44, height: 44,
                background: `${scanner.color}18`, border: `1px solid ${scanner.color}33`,
                borderRadius: "var(--radius-md)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 22, color: scanner.color,
              }}>
                {scanner.icon}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: 15, color: "var(--text-primary)" }}>{scanner.label}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: scanner.color, letterSpacing: "0.06em" }}>ACTIVE</div>
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
            { label: "Findings Loaded",  value: findingsCount || "—",       color: "var(--accent-cyan)" },
            { label: "Target Account",   value: scannedAccountId || "None", color: scannedAccountId ? "var(--low)" : "var(--text-muted)" },
            { label: "Scan Region",      value: "ap-south-1",               color: "var(--text-secondary)" },
            { label: "Scanners Active",  value: "4",                        color: "var(--low)" },
            { label: "Storage",          value: "DynamoDB + S3",            color: "var(--low)" },
          ].map((item) => (
            <div key={item.label}>
              <div style={{
                fontFamily: "var(--font-mono)", fontSize: 10,
                color: "var(--text-muted)", letterSpacing: "0.08em", marginBottom: 4,
              }}>
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