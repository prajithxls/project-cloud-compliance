import React, { createContext, useContext, useState, useEffect } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";

import Topbar from "./components/layout/Topbar";
import Sidebar from "./components/layout/Sidebar";
import ToastContainer from "./components/ui/Toast";
import AuthPage from "./pages/AuthPage";

import Dashboard    from "./pages/Dashboard";
import FindingsPage from "./pages/FindingsPage";
import ScanPage     from "./pages/ScanPage";
import ReportsPage  from "./pages/ReportsPage";
import HistoryPage from "./pages/HistoryPage";

import { useFindings, useScan, useToast, useScanHistory } from "./hooks/useCompliance";
import { computeStats, computeComplianceScore } from "./utils/helpers";
import { getCurrentUser, signOut } from "./services/auth";

const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

export default function App() {
  const [user, setUser] = useState(() => getCurrentUser());

  // ── THEME STATE (Only new addition) ────────────────────────────────────────
  const [theme, setTheme] = useState(() => localStorage.getItem("csc_theme") || "dark");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("csc_theme", theme);
  }, [theme]);
  // ───────────────────────────────────────────────────────────────────────────

  const { findings, loading, error, lastUpdated, scannedAccountId, refetch, clearFindings } = useFindings();
  const { toasts, addToast, removeToast } = useToast();
  const navigate = useNavigate();

  // After scan completes, fetch findings scoped to the target accountId
  const { scanning, scanLog, triggerScan } = useScan(async (accountId) => {
    // 1. Wait 8 seconds to give AWS time to finish scanning and writing to DynamoDB
    await new Promise(resolve => setTimeout(resolve, 8000));
    
    // 2. NOW fetch the findings (they will be ready!)
    const freshFindings = await refetch(accountId) || [];
    
    // 3. Calculate score and save the correct count to History
    const score = computeComplianceScore(freshFindings);
    addScanRecord(accountId, freshFindings.length, score);
    
    addToast(`Scan completed. ${freshFindings.length} findings found.`, "success");
  });
  
  const { history: scanHistory, addScanRecord, clearHistory } = useScanHistory(user?.userId);
  const stats = computeStats(findings);

  // accountId must always be a 12-digit target account — no own-account scanning
  const handleScan = (accountId) => {
    if (!accountId || accountId.length !== 12) {
      addToast("Please enter a valid 12-digit target account ID.", "error");
      return;
    }
    // Clear previous findings before starting a new scan
    clearFindings();
    triggerScan(accountId).catch(() =>
      addToast("Scan failed. Check API connection.", "error")
    );
    addScanRecord(accountId, "nil", 0, "Failed");
  };

  const handleLogin = () => {
    setUser(getCurrentUser());
    navigate("/");
  }

  const handleSignOut = () => {
    signOut();
    clearFindings();
    // clearHistory();
    setUser(null);
    navigate("/");
  };

  if (!user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <AppContext.Provider value={{ findings, loading, stats, addToast, scannedAccountId, scanHistory, addScanRecord }}>
      <div className="app-shell">
        <Topbar
          scanning={scanning}
          lastUpdated={lastUpdated}
          user={user}
          onSignOut={handleSignOut}
          theme={theme}        // 👈 Passed theme to Topbar
          setTheme={setTheme}  // 👈 Passed setTheme to Topbar
        />
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
            <Route path="/" element={
              <Dashboard
                findings={findings}
                loading={loading}
                scanning={scanning}
                scannedAccountId={scannedAccountId}
                onGoToScan={() => {}}
              />
            } />
            <Route path="/findings" element={
              <FindingsPage
                findings={findings}
                loading={loading}
                onRefresh={scannedAccountId ? () => refetch(scannedAccountId) : null}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/scan" element={
              <ScanPage
                scanning={scanning}
                scanLog={scanLog}
                onScan={handleScan}
                findingsCount={findings.length}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/reports" element={
              <ReportsPage
                findings={findings}
                addToast={addToast}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </main>

        <ToastContainer toasts={toasts} onRemove={removeToast} />
      </div>
    </AppContext.Provider>
  );
}