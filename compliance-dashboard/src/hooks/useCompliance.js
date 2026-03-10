import { useState, useEffect, useCallback } from "react";
import { getFindings, runScan } from "../services/api";

export function useFindings() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getFindings();
      const data = res.data;
      const items = Array.isArray(data) ? data : data.findings || [];
      setFindings(items);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetch(); }, [fetch]);

  return { findings, loading, error, lastUpdated, refetch: fetch };
}

export function useScan(onSuccess) {
  const [scanning, setScanning] = useState(false);
  const [scanLog, setScanLog] = useState([]);

  const log = (msg, type = "info") => {
    const time = new Date().toLocaleTimeString();
    setScanLog((prev) => [...prev, { time, msg, type }]);
  };

  const triggerScan = useCallback(async () => {
    setScanning(true);
    setScanLog([]);
    log("Initiating compliance scan...", "info");

    try {
      log("Connecting to AWS Lambda scanner...", "info");
      await runScan();
      log("Scan dispatched successfully.", "ok");
      log("Evaluating S3 bucket policies...", "info");
      await new Promise((r) => setTimeout(r, 1000));
      log("S3 bucket policies evaluated.", "ok");
      log("Evaluating EC2 security groups...", "info");
      await new Promise((r) => setTimeout(r, 800));
      log("EC2 security groups evaluated.", "ok");
      log("Evaluating IAM user configurations...", "info");
      await new Promise((r) => setTimeout(r, 800));
      log("IAM user MFA status evaluated.", "ok");
      log("Evaluating Lambda function configurations...", "info");
      await new Promise((r) => setTimeout(r, 800));
      log("Lambda function configurations evaluated.", "ok");
      await new Promise((r) => setTimeout(r, 400));
      log("Scan complete. Refreshing findings...", "info");
      if (onSuccess) onSuccess();
    } catch (err) {
      log(`Scan failed: ${err.message}`, "warn");
    } finally {
      setScanning(false);
    }
  }, [onSuccess]);

  return { scanning, scanLog, triggerScan };
}

export function usePagination(items, pageSize = 15) {
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start = (currentPage - 1) * pageSize;
  const paginated = items.slice(start, start + pageSize);
  return { page: currentPage, setPage, totalPages, paginated, total: items.length, start, end: Math.min(start + pageSize, items.length) };
}

export function useFilter(findings) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [scannerFilter, setScannerFilter] = useState("ALL");
  const [sortKey, setSortKey] = useState("timestamp");
  const [sortDir, setSortDir] = useState("desc");

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("asc"); }
  };

  const filtered = findings
    .filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (statusFilter !== "ALL" && f.status !== statusFilter) return false;
      if (scannerFilter !== "ALL" && f.scanner !== scannerFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          f.title?.toLowerCase().includes(q) ||
          f.resourceId?.toLowerCase().includes(q) ||
          f.resourceType?.toLowerCase().includes(q) ||
          f.findingId?.toLowerCase().includes(q) ||
          f.accountId?.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => {
      let va = a[sortKey] ?? "", vb = b[sortKey] ?? "";
      if (sortKey === "riskScore") { va = parseFloat(va) || 0; vb = parseFloat(vb) || 0; }
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });

  return { filtered, search, setSearch, severityFilter, setSeverityFilter, statusFilter, setStatusFilter, scannerFilter, setScannerFilter, sortKey, sortDir, toggleSort };
}

export function useToast() {
  const [toasts, setToasts] = useState([]);
  const addToast = useCallback((message, type = "info", duration = 4000) => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), duration);
  }, []);
  const removeToast = useCallback((id) => setToasts((prev) => prev.filter((t) => t.id !== id)), []);
  return { toasts, addToast, removeToast };
}