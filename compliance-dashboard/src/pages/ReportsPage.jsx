import React, { useState } from "react";
import { getReportDownloadUrl, refreshFindings } from "../services/api";
import { formatDate } from "../utils/helpers";

// ── Load jsPDF via script tag ─────────────────────────────────────────────────
function loadJsPDF() {
  return new Promise((resolve, reject) => {
    if (window.jspdf?.jsPDF) { resolve(window.jspdf.jsPDF); return; }
    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js";
    script.onload = () => {
      const ctor = window.jspdf?.jsPDF;
      ctor ? resolve(ctor) : reject(new Error("jsPDF not found on window.jspdf"));
    };
    script.onerror = () => reject(new Error("Failed to load jsPDF script"));
    document.head.appendChild(script);
  });
}

// ── PDF generation ────────────────────────────────────────────────────────────
async function generatePDF(findings) {
  const jsPDF = await loadJsPDF();
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const W = 210;
  doc.setFillColor(6, 15, 26);
  doc.rect(0, 0, W, 297, "F");
  const margin = 16;
  const contentW = W - margin * 2;
  let y = 0;

  const now = new Date();
  const dateStr = now.toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" });
  const timeStr = now.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

  const counts = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL").length,
    HIGH:     findings.filter(f => f.severity === "HIGH").length,
    MEDIUM:   findings.filter(f => f.severity === "MEDIUM").length,
    LOW:      findings.filter(f => f.severity === "LOW").length,
  };

  const accountId = findings[0]?.accountId || "N/A";

  // Header
  doc.setFillColor(8, 20, 32);
  doc.rect(0, 0, W, 52, "F");
  doc.setFillColor(0, 212, 255);
  doc.rect(0, 52, W, 1.5, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.setTextColor(232, 244, 253);
  doc.text("Cloud Security Compliance", margin, 20);
  doc.text("and Audit Management System", margin, 30);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(122, 154, 184);
  doc.text("COMPLIANCE AUDIT REPORT", margin, 40);
  doc.text(`Generated: ${dateStr} at ${timeStr}`, margin, 47);
  doc.setFillColor(14, 36, 58);
  doc.roundedRect(W - 76, 12, 62, 16, 3, 3, "F");
  doc.setFontSize(8);
  doc.setTextColor(0, 212, 255);
  doc.setFont("helvetica", "bold");
  doc.text("AWS ACCOUNT", W - 45, 20, { align: "center" });
  doc.setTextColor(232, 244, 253);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(accountId, W - 45, 26, { align: "center" });
  y = 62;

  // Executive Summary
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(232, 244, 253);
  doc.setFillColor(14, 26, 40);
  doc.rect(0, y - 4, W, 12, "F");
  doc.text("Executive Summary", margin, y + 4);
  y += 16;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(80, 110, 140);
  const summary =
    `This report presents the results of an automated compliance scan conducted on AWS account ${accountId}. ` +
    `A total of ${findings.length} findings were identified across S3, EC2, IAM, and Lambda services. ` +
    `Immediate remediation is recommended for all CRITICAL and HIGH severity findings.`;
  const summaryLines = doc.splitTextToSize(summary, contentW);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 5.5 + 6;

  // Severity Boxes
  const boxes = [
    { label: "CRITICAL", count: counts.CRITICAL, r: 220, g: 40,  b: 80  },
    { label: "HIGH",     count: counts.HIGH,     r: 255, g: 140, b: 0   },
    { label: "MEDIUM",   count: counts.MEDIUM,   r: 255, g: 190, b: 0   },
    { label: "LOW",      count: counts.LOW,       r: 0,   g: 200, b: 140 },
    { label: "TOTAL",    count: findings.length,  r: 0,   g: 180, b: 220 },
  ];
  const boxW = contentW / boxes.length - 3;
  boxes.forEach((box, i) => {
    const bx = margin + i * (boxW + 3.75);
    doc.setFillColor(14, 26, 40);
    doc.roundedRect(bx, y, boxW, 22, 3, 3, "F");
    doc.setDrawColor(box.r, box.g, box.b);
    doc.setLineWidth(0.5);
    doc.roundedRect(bx, y, boxW, 22, 3, 3, "S");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.setTextColor(box.r, box.g, box.b);
    doc.text(String(box.count), bx + boxW / 2, y + 13, { align: "center" });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(80, 110, 140);
    doc.text(box.label, bx + boxW / 2, y + 19, { align: "center" });
  });
  y += 30;

  // Scanner Breakdown
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setFillColor(14, 26, 40);
  doc.rect(0, y - 3, W, 10, "F");
  doc.setTextColor(232, 244, 253);
  doc.text("Scanner Breakdown", margin, y + 4);
  y += 13;
  const scanners = ["S3", "EC2", "IAM", "LAMBDA"];
  const tableHeaders = ["Scanner", "Total", "Critical", "High", "Medium", "Low"];
  const colWidths = [30, 22, 25, 22, 25, 22];
  let cx = margin;
  doc.setFillColor(20, 40, 60);
  doc.rect(margin, y - 4, contentW, 9, "F");
  tableHeaders.forEach((h, i) => {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(0, 212, 255);
    doc.text(h, cx + 2, y + 2);
    cx += colWidths[i];
  });
  y += 10;
  scanners.forEach((scanner, si) => {
    const sf = findings.filter(f => f.scanner === scanner);
    const row = [scanner, sf.length,
      sf.filter(f => f.severity === "CRITICAL").length,
      sf.filter(f => f.severity === "HIGH").length,
      sf.filter(f => f.severity === "MEDIUM").length,
      sf.filter(f => f.severity === "LOW").length,
    ];
    doc.setFillColor(si % 2 === 0 ? 12 : 16, si % 2 === 0 ? 22 : 28, si % 2 === 0 ? 36 : 44);
    doc.rect(margin, y - 4, contentW, 8, "F");
    cx = margin;
    row.forEach((val, i) => {
      doc.setFont("helvetica", i === 0 ? "bold" : "normal");
      doc.setFontSize(9);
      doc.setTextColor(i === 0 ? 232 : 122, i === 0 ? 244 : 154, i === 0 ? 253 : 184);
      doc.text(String(val), cx + 2, y + 1);
      cx += colWidths[i];
    });
    y += 9;
  });
  y += 8;

  // Findings Detail
  const addPageIfNeeded = (needed = 18) => {
    if (y + needed > 280) {
      doc.addPage();
      doc.setFillColor(6, 15, 26);
      doc.rect(0, 0, W, 297, "F");
      doc.setFillColor(8, 20, 32);
      doc.rect(0, 0, W, 10, "F");
      doc.setFillColor(0, 212, 255);
      doc.rect(0, 10, W, 0.8, "F");
      doc.setFont("helvetica", "italic");
      doc.setFontSize(8);
      doc.setTextColor(80, 110, 140);
      doc.text("Cloud Security Compliance and Audit Management System — Continued", margin, 7);
      y = 18;
    }
  };

  addPageIfNeeded(20);
  doc.setFillColor(14, 26, 40);
  doc.rect(0, y - 3, W, 10, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(232, 244, 253);
  doc.text("Findings Detail", margin, y + 4);
  y += 13;

  const severityColors = {
    CRITICAL: [220, 40, 80], HIGH: [255, 140, 0], MEDIUM: [255, 190, 0], LOW: [0, 200, 140],
  };
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  sorted.forEach((f) => {
    addPageIfNeeded(38);
    const [sr, sg, sb] = severityColors[f.severity] || [122, 154, 184];
    doc.setFillColor(12, 22, 34);
    doc.roundedRect(margin, y, contentW, 34, 2, 2, "F");
    doc.setFillColor(sr, sg, sb);
    doc.roundedRect(margin, y, 3, 34, 1, 1, "F");
    doc.setFillColor(Math.round(sr * 0.15), Math.round(sg * 0.15), Math.round(sb * 0.15));
    doc.roundedRect(margin + 6, y + 3, 22, 7, 1, 1, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(sr, sg, sb);
    doc.text(f.severity || "", margin + 17, y + 8, { align: "center" });
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(sr, sg, sb);
    doc.text(parseFloat(f.riskScore || 0).toFixed(1), margin + 32, y + 8.5);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(232, 244, 253);
    const titleLines = doc.splitTextToSize(f.title || "", contentW - 58);
    doc.text(titleLines[0], margin + 50, y + 8);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(80, 110, 140);
    doc.text(`${f.resourceType || ""} · ${(f.resourceId || "").slice(-55)}`, margin + 6, y + 17);
    doc.setFontSize(7);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(0, 180, 220);
    doc.text(`[${f.scanner || ""}]`, margin + 6, y + 24);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(60, 90, 110);
    doc.text(f.timestamp ? new Date(f.timestamp).toLocaleString() : "", margin + 20, y + 24);
    doc.setFontSize(7);
    doc.setTextColor(60, 100, 130);
    doc.text((f.complianceFramework || []).join("  ·  "), W - margin - 2, y + 24, { align: "right" });
    doc.setFont("helvetica", "italic");
    doc.setFontSize(7.5);
    doc.setTextColor(0, 160, 120);
    const remLines = doc.splitTextToSize("→ " + (f.remediation || ""), contentW - 12);
    doc.text(remLines[0], margin + 6, y + 31);
    y += 37;
  });

  // Footer
  addPageIfNeeded(20);
  y += 4;
  doc.setFillColor(8, 20, 32);
  doc.rect(0, y, W, 16, "F");
  doc.setFillColor(0, 212, 255);
  doc.rect(0, y, W, 0.8, "F");
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(80, 110, 140);
  doc.text("Cloud Security Compliance and Audit Management System", margin, y + 7);
  doc.text(`Report generated on ${dateStr}  ·  ${findings.length} total findings  ·  Account: ${accountId}`, margin, y + 13);
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(60, 90, 110);
    doc.text(`Page ${p} of ${totalPages}`, W - margin, 290, { align: "right" });
  }

  const filename = `CSC-AMS_Report_${accountId}_${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  return filename;
}

// ── Parse a clean date from CSV filename ─────────────────────────────────────
function parseCsvDate(filename) {
  // filename format: compliance_ACCOUNTID_YYYYMMDD_HHMMSS.csv
  const match = filename.match(/(\d{8})_(\d{6})\.csv$/);
  if (!match) return null;
  const d = match[1]; // e.g. "20260406"
  const t = match[2]; // e.g. "143022"
  const year  = d.slice(0, 4);
  const month = d.slice(4, 6);
  const day   = d.slice(6, 8);
  const hour  = t.slice(0, 2);
  const min   = t.slice(2, 4);
  return new Date(`${year}-${month}-${day}T${hour}:${min}:00Z`);
}

function formatCsvDate(filename) {
  const date = parseCsvDate(filename);
  if (!date) return null;
  return date.toLocaleDateString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
  }) + " at " + date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

// ── COMPONENT ─────────────────────────────────────────────────────────────────
export default function ReportsPage({ findings, addToast, scannedAccountId }) {
  // Only one CSV report is tracked in state — the one just generated this session
  const [currentReport,  setCurrentReport]  = useState(null); // { filename, generatedAt }
  const [generating,     setGenerating]     = useState(false);
  const [generatingPDF,  setGeneratingPDF]  = useState(false);

  const noScanYet = !scannedAccountId || findings.length === 0;

  const handleGenerateCSV = async () => {
    if (noScanYet) {
      addToast("Run a scan first before generating a report.", "error");
      return;
    }
    setGenerating(true);
    try {
      const res = await refreshFindings(scannedAccountId);
      const data = res.data;
      const filename = data.csvFile || `compliance_${scannedAccountId}_generated.csv`;
      setCurrentReport({ filename, generatedAt: new Date() });
      addToast("CSV report generated successfully.", "success");
    } catch (err) {
      addToast("Failed to generate CSV: " + err.message, "error");
    } finally {
      setGenerating(false);
    }
  };

  const handleGeneratePDF = async () => {
    if (noScanYet) {
      addToast("Run a scan first before generating a report.", "error");
      return;
    }
    setGeneratingPDF(true);
    try {
      const filename = await generatePDF(findings);
      addToast(`PDF downloaded: ${filename}`, "success");
    } catch (err) {
      addToast("PDF generation failed: " + err.message, "error");
    } finally {
      setGeneratingPDF(false);
    }
  };

  const handleDownloadCSV = () => {
    if (!currentReport) return;
    const url = getReportDownloadUrl(currentReport.filename);
    const a = document.createElement("a");
    a.href = url;
    a.download = currentReport.filename;
    a.click();
    addToast(`Downloading ${currentReport.filename}`, "info");
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Reports</div>
          <div className="page-title-sub">
            {scannedAccountId
              ? `Audit reports for account ${scannedAccountId}`
              : "Run a scan to generate reports"}
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            className="btn btn-secondary"
            onClick={handleGenerateCSV}
            disabled={generating || noScanYet}
          >
            {generating ? <><div className="spinner dark" /> Generating...</> : "⊕ Generate CSV Report"}
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleGeneratePDF}
            disabled={generatingPDF || noScanYet}
          >
            {generatingPDF ? <><div className="spinner dark" /> Building PDF...</> : "↓ Download PDF Report"}
          </button>
        </div>
      </div>

      {/* No scan yet — single clear message */}
      {noScanYet ? (
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "80px 20px",
          gap: 16,
          textAlign: "center",
        }}>
          <div style={{
            width: 64, height: 64, borderRadius: "50%",
            background: "var(--bg-elevated)",
            border: "1px solid var(--border)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 28,
          }}>
            🗐
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)" }}>
            No reports available
          </div>
          <div style={{ fontSize: 13, color: "var(--text-secondary)", maxWidth: 420, lineHeight: 1.6 }}>
            Complete a compliance scan on the <strong style={{ color: "var(--accent-cyan)" }}>Scan</strong> page first.
            Once scan results are loaded, you can generate PDF and CSV reports scoped to that account.
          </div>
        </div>
      ) : (
        <>
          {/* PDF Report Card */}
          <div className="card" style={{ marginBottom: 16, borderTop: "2px solid var(--accent-cyan)" }}>
            <div className="card-header">
              <span className="card-title">PDF Audit Report</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--low)" }}>
                RECOMMENDED
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
                  A fully formatted audit report for account{" "}
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                    {scannedAccountId}
                  </span>{" "}
                  — includes executive summary, severity breakdown, scanner analysis, and per-finding
                  remediation guidance. Ready to share with auditors or management.
                </p>
                <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
                  {["Executive summary", "Severity breakdown", "Scanner breakdown table", "Full findings detail", "Compliance frameworks", "Remediation guidance"].map(item => (
                    <div key={item} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
                      <span style={{ color: "var(--low)", fontSize: 10 }}>✓</span> {item}
                    </div>
                  ))}
                </div>
              </div>
              <button
                className="btn btn-secondary"
                style={{ fontSize: 14, padding: "12px 28px", flexShrink: 0, minWidth: 210 }}
                onClick={handleGeneratePDF}
                disabled={generatingPDF}
              >
                {generatingPDF
                  ? <><div className="spinner dark" /> Building PDF...</>
                  : `↓ Download PDF (${findings.length} findings)`}
              </button>
            </div>
          </div>

          {/* CSV Report Card */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">CSV Report</span>
              {currentReport && (
                <span style={{
                  fontFamily: "var(--font-mono)", fontSize: 10,
                  color: "var(--low)", background: "var(--bg-elevated)",
                  border: "1px solid var(--low)33", padding: "2px 10px", borderRadius: "20px",
                }}>
                  READY
                </span>
              )}
            </div>

            {!currentReport ? (
              /* Not generated yet */
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: 16,
              }}>
                <div>
                  <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 0 }}>
                    Export all{" "}
                    <strong style={{ color: "var(--text-primary)" }}>{findings.length} findings</strong>{" "}
                    for account{" "}
                    <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                      {scannedAccountId}
                    </span>{" "}
                    as a CSV file. Suitable for importing into spreadsheets, ticketing systems, or SIEM tools.
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: 14, padding: "12px 28px", flexShrink: 0, minWidth: 210 }}
                  onClick={handleGenerateCSV}
                  disabled={generating}
                >
                  {generating
                    ? <><div className="spinner dark" /> Generating...</>
                    : "⊕ Generate CSV Report"}
                </button>
              </div>
            ) : (
              /* Report ready — show single row */
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "14px 0",
                gap: 16,
                flexWrap: "wrap",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                  <div style={{
                    width: 42, height: 42,
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-md)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 20,
                  }}>
                    🗂
                  </div>
                  <div>
                    <div style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: 13,
                      color: "var(--text-primary)",
                      fontWeight: 600,
                      marginBottom: 4,
                    }}>
                      {currentReport.filename}
                    </div>
                    <div style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: 11,
                      color: "var(--text-muted)",
                    }}>
                      {findings.length} findings · Account {scannedAccountId} ·{" "}
                      Generated {currentReport.generatedAt.toLocaleString("en-GB", {
                        day: "2-digit", month: "short", year: "numeric",
                        hour: "2-digit", minute: "2-digit",
                      })}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: 12 }}
                    onClick={handleGenerateCSV}
                    disabled={generating}
                  >
                    {generating ? "Regenerating..." : "↺ Regenerate"}
                  </button>
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: 14, padding: "10px 24px" }}
                    onClick={handleDownloadCSV}
                  >
                    ↓ Download CSV
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}