import React, { createContext, useContext } from "react";
import { Routes, Route } from "react-router-dom";

import Topbar from "./components/layout/Topbar";
import Sidebar from "./components/layout/Sidebar";
import ToastContainer from "./components/ui/Toast";

import Dashboard from "./pages/Dashboard";
import FindingsPage from "./pages/FindingsPage";
import ScanPage from "./pages/ScanPage";
import ReportsPage from "./pages/ReportsPage";

import { useFindings, useScan, useToast } from "./hooks/useCompliance";
import { computeStats } from "./utils/helpers";

// ============================================================
// Context for global state sharing
// ============================================================
const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

export default function App() {
  const { findings, loading, error, lastUpdated, refetch } = useFindings();
  const { toasts, addToast, removeToast } = useToast();
  const { scanning, scanLog, triggerScan } = useScan(() => {
    setTimeout(refetch, 2000); // Refetch after scan settles
    addToast("Scan completed. Findings refreshed.", "success");
  });

  const stats = computeStats(findings);

  const handleScan = () => {
    triggerScan().catch(() => addToast("Scan failed. Check API connection.", "error"));
  };

  return (
    <AppContext.Provider value={{ findings, loading, stats, addToast }}>
      <div className="app-shell">
        <Topbar scanning={scanning} lastUpdated={lastUpdated} />
        <Sidebar criticalCount={stats.CRITICAL} />

        <main className="main-content">
          {error && (
            <div style={{
              background: "var(--critical-dim)",
              border: "1px solid rgba(255,59,92,0.3)",
              borderRadius: "var(--radius-md)",
              padding: "12px 16px",
              marginBottom: 20,
              color: "var(--critical)",
              fontFamily: "var(--font-mono)",
              fontSize: 12,
            }}>
              ⚠ API Error: {error} — Check your API_BASE in src/services/api.js
            </div>
          )}

          <Routes>
            <Route
              path="/"
              element={
                <Dashboard
                  findings={findings}
                  loading={loading}
                  scanning={scanning}
                  onScan={handleScan}
                />
              }
            />
            <Route
              path="/findings"
              element={
                <FindingsPage
                  findings={findings}
                  loading={loading}
                  onRefresh={refetch}
                />
              }
            />
            <Route
              path="/scan"
              element={
                <ScanPage
                  scanning={scanning}
                  scanLog={scanLog}
                  onScan={handleScan}
                  findingsCount={findings.length}
                />
              }
            />
            <Route
              path="/reports"
              element={
                <ReportsPage findings={findings} addToast={addToast} />
              }
            />
          </Routes>
        </main>

        <ToastContainer toasts={toasts} onRemove={removeToast} />
      </div>
    </AppContext.Provider>
  );
}
