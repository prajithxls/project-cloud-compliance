import React, { useEffect } from "react";
import { useLocation } from "react-router-dom";
import FindingsTable from "../components/ui/FindingsTable";
import { useFilter, usePagination } from "../hooks/useCompliance";

export default function FindingsPage({ findings, loading, onRefresh }) {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const defaultScanner = params.get("scanner") || "ALL";

  const {
    filtered,
    search, setSearch,
    severityFilter, setSeverityFilter,
    statusFilter, setStatusFilter,
    scannerFilter, setScannerFilter,
    sortKey, sortDir, toggleSort,
  } = useFilter(findings);

  const {
    page, setPage, totalPages, paginated, total, start, end,
  } = usePagination(filtered, 15);

  // Pre-set scanner filter from URL
  useEffect(() => {
    setScannerFilter(defaultScanner);
  }, [defaultScanner, setScannerFilter]);

  // Unique scanners for filter dropdown
  const scanners = ["ALL", ...new Set(findings.map((f) => f.scanner).filter(Boolean))];

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Findings</div>
          <div className="page-title-sub">
            {total} findings · Sorted by {sortKey} {sortDir === "asc" ? "↑" : "↓"}
          </div>
        </div>
        <button
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={loading}
        >
          {loading ? <><div className="spinner" /> Refreshing</> : "⟳ Refresh"}
        </button>
      </div>

      {/* Controls */}
      <div className="table-controls">
        <div className="search-input-wrapper">
          <span className="search-icon">⌕</span>
          <input
            className="search-input"
            placeholder="Search findings, resources, titles..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          />
        </div>

        <select
          className="filter-select"
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          className="filter-select"
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
        >
          <option value="ALL">All Status</option>
          <option value="OPEN">Open</option>
          <option value="RESOLVED">Resolved</option>
        </select>

        <select
          className="filter-select"
          value={scannerFilter}
          onChange={(e) => { setScannerFilter(e.target.value); setPage(1); }}
        >
          {scanners.map((s) => (
            <option key={s} value={s}>{s === "ALL" ? "All Scanners" : s}</option>
          ))}
        </select>

        {(search || severityFilter !== "ALL" || statusFilter !== "ALL" || scannerFilter !== "ALL") && (
          <button
            className="btn btn-ghost"
            onClick={() => {
              setSearch("");
              setSeverityFilter("ALL");
              setStatusFilter("ALL");
              setScannerFilter("ALL");
              setPage(1);
            }}
          >
            ✕ Clear
          </button>
        )}
      </div>

      {/* Table */}
      <FindingsTable
        findings={paginated}
        sortKey={sortKey}
        sortDir={sortDir}
        onSort={(key) => { toggleSort(key); setPage(1); }}
        loading={loading}
      />

      {/* Pagination */}
      {!loading && total > 0 && (
        <div className="pagination">
          <div className="pagination-info">
            Showing {start + 1}–{end} of {total} findings
          </div>
          <div className="pagination-controls">
            <button
              className="page-btn"
              onClick={() => setPage(1)}
              disabled={page === 1}
            >
              «
            </button>
            <button
              className="page-btn"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              ‹
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const start = Math.max(1, Math.min(page - 2, totalPages - 4));
              const p = start + i;
              return (
                <button
                  key={p}
                  className={`page-btn${page === p ? " active" : ""}`}
                  onClick={() => setPage(p)}
                >
                  {p}
                </button>
              );
            })}
            <button
              className="page-btn"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              ›
            </button>
            <button
              className="page-btn"
              onClick={() => setPage(totalPages)}
              disabled={page === totalPages}
            >
              »
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
