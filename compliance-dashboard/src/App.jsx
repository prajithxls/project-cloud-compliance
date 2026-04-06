import React, { createContext, useContext, useState } from "react";
import { Routes, Route } from "react-router-dom";

import Topbar from "./components/layout/Topbar";
import Sidebar from "./components/layout/Sidebar";
import ToastContainer from "./components/ui/Toast";
import AuthPage from "./pages/AuthPage";

import Dashboard    from "./pages/Dashboard";
import FindingsPage from "./pages/FindingsPage";
import ScanPage     from "./pages/ScanPage";
import ReportsPage  from "./pages/ReportsPage";

import { useFindings, useScan, useToast } from "./hooks/useCompliance";
import { computeStats } from "./utils/helpers";
import { getCurrentUser, signOut } from "./services/auth";

const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

export default function App() {
  const [user, setUser] = useState(() => getCurrentUser());

  const { findings, loading, error, lastUpdated, scannedAccountId, refetch, clearFindings } = useFindings();
  const { toasts, addToast, removeToast } = useToast();

  // After scan completes, fetch findings scoped to the target accountId
  const { scanning, scanLog, triggerScan } = useScan((accountId) => {
    setTimeout(() => refetch(accountId), 2000);
    addToast(`Scan completed for account ${accountId}. Findings refreshed.`, "success");
  });

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
  };

  const handleLogin = () => setUser(getCurrentUser());

  const handleSignOut = () => {
    signOut();
    clearFindings(); // wipe findings from memory on logout
    setUser(null);
  };

  if (!user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <AppContext.Provider value={{ findings, loading, stats, addToast, scannedAccountId }}>
      <div className="app-shell">
        <Topbar
          scanning={scanning}
          lastUpdated={lastUpdated}
          user={user}
          onSignOut={handleSignOut}
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
          </Routes>
        </main>

        <ToastContainer toasts={toasts} onRemove={removeToast} />
      </div>
    </AppContext.Provider>
  );
}