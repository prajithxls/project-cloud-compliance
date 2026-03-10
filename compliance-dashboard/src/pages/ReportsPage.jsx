import React, { useState, useEffect } from "react";
import { listReports, getReportDownloadUrl, refreshFindings } from "../services/api";
import { formatDate } from "../utils/helpers";

// ── Load jsPDF via script tag (dynamic import doesn't work with UMD builds) ───
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

  // Set dark background on page 1 (subsequent pages handled in addPageIfNeeded)
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
    OPEN:     findings.filter(f => f.status === "OPEN").length,
  };

  const accountId = findings[0]?.accountId || "N/A";

  // ── HEADER ────────────────────────────────────────────────────────────────
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

  // ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
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
    `A total of ${findings.length} findings were identified across S3, EC2, and IAM services. ` +
    `Immediate remediation is recommended for all CRITICAL and HIGH severity findings.`;
  const summaryLines = doc.splitTextToSize(summary, contentW);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 5.5 + 6;

  // ── SEVERITY BOXES ────────────────────────────────────────────────────────
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

  // ── SCANNER BREAKDOWN ─────────────────────────────────────────────────────
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
    const row = [
      scanner,
      sf.length,
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

  // ── FINDINGS DETAIL ───────────────────────────────────────────────────────
  const addPageIfNeeded = (needed = 18) => {
    if (y + needed > 280) {
      doc.addPage();
      // Dark background for new page
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
    CRITICAL: [220, 40,  80 ],
    HIGH:     [255, 140, 0  ],
    MEDIUM:   [255, 190, 0  ],
    LOW:      [0,   200, 140],
  };

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) =>
    (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
  );

  sorted.forEach((f) => {
    addPageIfNeeded(38);
    const [sr, sg, sb] = severityColors[f.severity] || [122, 154, 184];

    // Card background — taller to give each row room
    doc.setFillColor(12, 22, 34);
    doc.roundedRect(margin, y, contentW, 34, 2, 2, "F");

    // Left severity bar
    doc.setFillColor(sr, sg, sb);
    doc.roundedRect(margin, y, 3, 34, 1, 1, "F");

    // ROW 1: Severity badge + risk score + title  (y+9)
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

    // ROW 2: Resource type + ID  (y+17)
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(80, 110, 140);
    const resourceText = `${f.resourceType || ""} · ${(f.resourceId || "").slice(-55)}`;
    doc.text(resourceText, margin + 6, y + 17);

    // ROW 3: Scanner tag + timestamp (left) | Compliance frameworks (right)  (y+24)
    doc.setFontSize(7);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(0, 180, 220);
    doc.text(`[${f.scanner || ""}]`, margin + 6, y + 24);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(60, 90, 110);
    doc.text(f.timestamp ? new Date(f.timestamp).toLocaleString() : "", margin + 20, y + 24);

    const frameworks = (f.complianceFramework || []).join("  ·  ");
    doc.setFontSize(7);
    doc.setTextColor(60, 100, 130);
    doc.text(frameworks, W - margin - 2, y + 24, { align: "right" });

    // ROW 4: Remediation on its own line  (y+31)
    doc.setFont("helvetica", "italic");
    doc.setFontSize(7.5);
    doc.setTextColor(0, 160, 120);
    const remLines = doc.splitTextToSize("→ " + (f.remediation || ""), contentW - 12);
    doc.text(remLines[0], margin + 6, y + 31);

    y += 37;
  });

  // ── FOOTER (no CONFIDENTIAL) ──────────────────────────────────────────────
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

  // Page numbers on every page
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(60, 90, 110);
    doc.text(`Page ${p} of ${totalPages}`, W - margin, 290, { align: "right" });
  }

  const filename = `CSC-AMS_Report_${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  return filename;
}

// ── COMPONENT ─────────────────────────────────────────────────────────────────
export default function ReportsPage({ findings, addToast }) {
  const [reports, setReports]               = useState([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [generating, setGenerating]         = useState(false);
  const [generatingPDF, setGeneratingPDF]   = useState(false);

  const fetchReports = async () => {
    setLoadingReports(true);
    try {
      const keys = await listReports();
      setReports(keys);
    } catch {
      setReports([]);
    } finally {
      setLoadingReports(false);
    }
  };

  useEffect(() => { fetchReports(); }, []);

  const handleGenerateCSV = async () => {
    setGenerating(true);
    try {
      await refreshFindings();
      addToast("New CSV report generated in S3", "success");
      await fetchReports();
    } catch (err) {
      addToast("Failed to generate CSV: " + err.message, "error");
    } finally {
      setGenerating(false);
    }
  };

  const handleGeneratePDF = async () => {
    if (!findings.length) {
      addToast("No findings to generate a report from. Run a scan first.", "error");
      return;
    }
    setGeneratingPDF(true);
    try {
      const filename = await generatePDF(findings);
      addToast(`PDF downloaded: ${filename}`, "success");
    } catch (err) {
      console.error(err);
      addToast("PDF generation failed: " + err.message, "error");
    } finally {
      setGeneratingPDF(false);
    }
  };

  const handleDownload = (filename) => {
    const url = getReportDownloadUrl(filename);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    addToast(`Downloading ${filename}`, "info");
  };

  const counts = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL").length,
    HIGH:     findings.filter(f => f.severity === "HIGH").length,
    MEDIUM:   findings.filter(f => f.severity === "MEDIUM").length,
    LOW:      findings.filter(f => f.severity === "LOW").length,
    OPEN:     findings.filter(f => f.status === "OPEN").length,
  };

  return (
    <div>
      {/* Page Header — only PDF and CSV buttons, no "Export Current View" */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Reports</div>
          <div className="page-title-sub">
            Generate and download audit reports for compliance reviews
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            className="btn btn-secondary"
            onClick={handleGenerateCSV}
            disabled={generating}
          >
            {generating
              ? <><div className="spinner dark" /> Generating...</>
              : "⊕ Generate New Report"}
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleGeneratePDF}
            disabled={generatingPDF}
          >
            {generatingPDF
              ? <><div className="spinner dark" /> Building PDF...</>
              : "↓ Download PDF Report"}
          </button>
        </div>
      </div>

      {/* PDF Report Card */}
      <div className="card" style={{ marginBottom: 16, borderTop: "2px solid var(--accent-cyan)" }}>
        <div className="card-header">
          <span className="card-title"> PDF Audit Report</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--low)" }}>RECOMMENDED</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div style={{ flex: 1 }}>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 10 }}>
              Generate a fully formatted PDF report with executive summary, severity breakdown,
              scanner analysis, and detailed findings — ready to present to auditors or management.
            </p>
            <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
              {[
                "Executive summary",
                "Severity breakdown",
                "Scanner breakdown table",
                "Full findings detail",
                "Compliance frameworks",
                "Remediation guidance",
              ].map(item => (
                <div key={item} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
                  <span style={{ color: "var(--low)", fontSize: 10 }}>✓</span> {item}
                </div>
              ))}
            </div>
          </div>
          <button
            className="btn btn-secondary"
            style={{ fontSize: 14, padding: "12px 28px", flexShrink: 0, minWidth: 200 }}
            onClick={handleGeneratePDF}
            disabled={generatingPDF || !findings.length}
          >
            {generatingPDF
              ? <><div className="spinner dark" /> Building PDF...</>
              : `↓ Download PDF (${findings.length} findings)`}
          </button>
        </div>
      </div>

      {/* CSV Reports from S3 */}
      <div className="card">
        <div className="card-header">
          <span className="card-title"> CSV Reports (S3 Storage)</span>
          <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={fetchReports}>
            ⟳ Refresh
          </button>
        </div>

        {loadingReports ? (
          <div className="loading-overlay" style={{ minHeight: 80 }}>
            <div className="spinner" />
            <div className="loading-text">FETCHING FROM S3...</div>
          </div>
        ) : reports.length > 0 ? (
          <div className="report-list">
            {reports.map((filename, i) => {
              const dateStr = filename.match(/\d{8}_\d{6}/)?.[0];
              const date = dateStr
                ? formatDate(dateStr.slice(0,4) + "-" + dateStr.slice(4,6) + "-" + dateStr.slice(6,8))
                : "Unknown date";
              return (
                <div key={filename} className="report-item">
                  <div className="report-item-info">
                    <div className="report-icon">🗂</div>
                    <div>
                      <div className="report-name">{filename}</div>
                      <div className="report-meta">
                        Generated {date} · CSV · S3 Storage
                        {i === 0 && (
                          <span style={{
                            marginLeft: 8,
                            background: "var(--low-dim)",
                            color: "var(--low)",
                            padding: "1px 6px",
                            borderRadius: "var(--radius-sm)",
                            fontSize: 10,
                            fontWeight: 700,
                          }}>LATEST</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <button className="btn btn-secondary" onClick={() => handleDownload(filename)}>
                    ↓ Download CSV
                  </button>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon"></div>
            <div className="empty-state-title">No CSV reports in S3</div>
            <div className="empty-state-sub">
              Click "Generate New Report" above to create one, or download the PDF report directly.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}