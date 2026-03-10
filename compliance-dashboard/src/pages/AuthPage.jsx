import React, { useState } from "react";
import { signIn, signUp, confirmSignUp, resendCode, forgotPassword, confirmForgotPassword } from "../services/auth";

// ── views: "login" | "signup" | "verify" | "forgot" | "reset"
export default function AuthPage({ onLogin }) {
  const [view,     setView]     = useState("login");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [code,     setCode]     = useState("");
  const [newPass,  setNewPass]  = useState("");
  const [error,    setError]    = useState("");
  const [info,     setInfo]     = useState("");
  const [loading,  setLoading]  = useState(false);

  const reset = () => { setError(""); setInfo(""); };

  // ── LOGIN ──────────────────────────────────────────────────────────────────
  const handleLogin = async () => {
    reset();
    if (!email || !password) { setError("Please enter your email and password."); return; }
    setLoading(true);
    try {
      await signIn(email, password);
      onLogin();
    } catch (e) {
      if (e.message.includes("not confirmed")) {
        setInfo("Your account is not verified yet. Enter the code sent to your email.");
        setView("verify");
      } else {
        setError(e.message);
      }
    } finally { setLoading(false); }
  };

  // ── SIGN UP ────────────────────────────────────────────────────────────────
  const handleSignUp = async () => {
    reset();
    if (!email || !password) { setError("Email and password are required."); return; }
    if (password !== confirm) { setError("Passwords do not match."); return; }
    if (password.length < 8)  { setError("Password must be at least 8 characters."); return; }
    setLoading(true);
    try {
      await signUp(email, password);
      setInfo("Account created! Check your email for a verification code.");
      setView("verify");
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── VERIFY ─────────────────────────────────────────────────────────────────
  const handleVerify = async () => {
    reset();
    if (!code) { setError("Enter the 6-digit code from your email."); return; }
    setLoading(true);
    try {
      await confirmSignUp(email, code);
      setInfo("Email verified! Signing you in...");
      await signIn(email, password);
      onLogin();
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── FORGOT PASSWORD ────────────────────────────────────────────────────────
  const handleForgot = async () => {
    reset();
    if (!email) { setError("Enter your email address."); return; }
    setLoading(true);
    try {
      await forgotPassword(email);
      setInfo("Reset code sent to your email.");
      setView("reset");
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── RESET PASSWORD ─────────────────────────────────────────────────────────
  const handleReset = async () => {
    reset();
    if (!code || !newPass) { setError("Enter the code and your new password."); return; }
    if (newPass.length < 8) { setError("Password must be at least 8 characters."); return; }
    setLoading(true);
    try {
      await confirmForgotPassword(email, code, newPass);
      setInfo("Password reset! You can now log in.");
      setView("login");
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── SHARED STYLES ──────────────────────────────────────────────────────────
  const inputStyle = {
    width: "100%",
    padding: "11px 14px",
    background: "#0a1828",
    border: "1px solid #1a3a5c",
    borderRadius: 8,
    color: "#e8f4fd",
    fontFamily: "var(--font-mono)",
    fontSize: 14,
    outline: "none",
    boxSizing: "border-box",
    transition: "border-color 0.15s",
  };

  const labelStyle = {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "#4a7a9b",
    letterSpacing: "0.08em",
    marginBottom: 6,
    display: "block",
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#060f1a",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20,
    }}>
      {/* Background grid effect */}
      <div style={{
        position: "fixed", inset: 0, opacity: 0.03,
        backgroundImage: "linear-gradient(#00d4ff 1px, transparent 1px), linear-gradient(90deg, #00d4ff 1px, transparent 1px)",
        backgroundSize: "40px 40px",
        pointerEvents: "none",
      }} />

      <div style={{
        width: "100%",
        maxWidth: 420,
        background: "#0a1828",
        border: "1px solid #1a3a5c",
        borderRadius: 16,
        overflow: "hidden",
        boxShadow: "0 24px 80px rgba(0,0,0,0.6)",
        position: "relative",
      }}>
        {/* Top accent line */}
        <div style={{ height: 3, background: "linear-gradient(90deg, #00d4ff, #0066cc)" }} />

        <div style={{ padding: "36px 36px 32px" }}>
          {/* Logo / Title */}
          <div style={{ textAlign: "center", marginBottom: 32 }}>
            <div style={{
              width: 52, height: 52,
              background: "linear-gradient(135deg, #00d4ff22, #0066cc22)",
              border: "1px solid #00d4ff44",
              borderRadius: 14,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 24, margin: "0 auto 16px",
            }}>
              🛡
            </div>
            <div style={{
              fontFamily: "var(--font-display, monospace)",
              fontSize: 17,
              fontWeight: 800,
              color: "#e8f4fd",
              letterSpacing: "0.02em",
              lineHeight: 1.3,
            }}>
              Cloud Security Compliance
            </div>
            <div style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 10,
              color: "#00d4ff",
              letterSpacing: "0.12em",
              marginTop: 4,
            }}>
              & AUDIT MANAGEMENT SYSTEM
            </div>
          </div>

          {/* View Title */}
          <div style={{
            fontFamily: "var(--font-mono, monospace)",
            fontSize: 11,
            color: "#4a7a9b",
            letterSpacing: "0.1em",
            marginBottom: 20,
            textAlign: "center",
          }}>
            {view === "login"  && "SIGN IN TO YOUR ACCOUNT"}
            {view === "signup" && "CREATE AN ACCOUNT"}
            {view === "verify" && "VERIFY YOUR EMAIL"}
            {view === "forgot" && "RESET PASSWORD"}
            {view === "reset"  && "SET NEW PASSWORD"}
          </div>

          {/* Error / Info */}
          {error && (
            <div style={{
              background: "#2a0a14",
              border: "1px solid #ff3b5c44",
              borderRadius: 8,
              padding: "10px 14px",
              marginBottom: 16,
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 12,
              color: "#ff6b8a",
            }}>
              ⚠ {error}
            </div>
          )}
          {info && (
            <div style={{
              background: "#0a2a1a",
              border: "1px solid #00c87a44",
              borderRadius: 8,
              padding: "10px 14px",
              marginBottom: 16,
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 12,
              color: "#00c87a",
            }}>
              ✓ {info}
            </div>
          )}

          {/* ── LOGIN FORM ── */}
          {view === "login" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>EMAIL ADDRESS</label>
                <input style={inputStyle} type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"}
                  onKeyDown={e => e.key === "Enter" && handleLogin()} />
              </div>
              <div>
                <label style={labelStyle}>PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="••••••••"
                  value={password} onChange={e => setPassword(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"}
                  onKeyDown={e => e.key === "Enter" && handleLogin()} />
              </div>
              <div style={{ textAlign: "right", marginTop: -8 }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#00d4ff", cursor: "pointer" }}
                  onClick={() => { reset(); setView("forgot"); }}>
                  Forgot password?
                </span>
              </div>
              <button className="btn btn-primary" style={{ width: "100%", padding: "12px", fontSize: 14, marginTop: 4 }}
                onClick={handleLogin} disabled={loading}>
                {loading ? <><div className="spinner dark" /> Signing in...</> : "→ Sign In"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#4a7a9b" }}>
                No account?{" "}
                <span style={{ color: "#00d4ff", cursor: "pointer" }} onClick={() => { reset(); setView("signup"); }}>
                  Create one
                </span>
              </div>
            </div>
          )}

          {/* ── SIGNUP FORM ── */}
          {view === "signup" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>EMAIL ADDRESS</label>
                <input style={inputStyle} type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"} />
              </div>
              <div>
                <label style={labelStyle}>PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="Min. 8 characters"
                  value={password} onChange={e => setPassword(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"} />
              </div>
              <div>
                <label style={labelStyle}>CONFIRM PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="••••••••"
                  value={confirm} onChange={e => setConfirm(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"}
                  onKeyDown={e => e.key === "Enter" && handleSignUp()} />
              </div>
              <button className="btn btn-primary" style={{ width: "100%", padding: "12px", fontSize: 14 }}
                onClick={handleSignUp} disabled={loading}>
                {loading ? <><div className="spinner dark" /> Creating account...</> : "→ Create Account"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#4a7a9b" }}>
                Already have an account?{" "}
                <span style={{ color: "#00d4ff", cursor: "pointer" }} onClick={() => { reset(); setView("login"); }}>
                  Sign in
                </span>
              </div>
            </div>
          )}

          {/* ── VERIFY FORM ── */}
          {view === "verify" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#4a7a9b", marginBottom: 4 }}>
                A 6-digit code was sent to<br />
                <span style={{ color: "#e8f4fd" }}>{email}</span>
              </div>
              <div>
                <label style={labelStyle}>VERIFICATION CODE</label>
                <input style={{ ...inputStyle, fontSize: 22, textAlign: "center", letterSpacing: "0.3em" }}
                  type="text" placeholder="000000" maxLength={6}
                  value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"}
                  onKeyDown={e => e.key === "Enter" && handleVerify()} />
              </div>
              <button className="btn btn-primary" style={{ width: "100%", padding: "12px", fontSize: 14 }}
                onClick={handleVerify} disabled={loading}>
                {loading ? <><div className="spinner dark" /> Verifying...</> : "✓ Verify Email"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#4a7a9b" }}>
                Didn't get it?{" "}
                <span style={{ color: "#00d4ff", cursor: "pointer" }}
                  onClick={() => resendCode(email).then(() => setInfo("Code resent!")).catch(e => setError(e.message))}>
                  Resend code
                </span>
              </div>
            </div>
          )}

          {/* ── FORGOT PASSWORD FORM ── */}
          {view === "forgot" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>EMAIL ADDRESS</label>
                <input style={inputStyle} type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"}
                  onKeyDown={e => e.key === "Enter" && handleForgot()} />
              </div>
              <button className="btn btn-primary" style={{ width: "100%", padding: "12px", fontSize: 14 }}
                onClick={handleForgot} disabled={loading}>
                {loading ? <><div className="spinner dark" /> Sending...</> : "→ Send Reset Code"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#4a7a9b" }}>
                <span style={{ color: "#00d4ff", cursor: "pointer" }} onClick={() => { reset(); setView("login"); }}>
                  ← Back to Sign In
                </span>
              </div>
            </div>
          )}

          {/* ── RESET PASSWORD FORM ── */}
          {view === "reset" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>RESET CODE (from email)</label>
                <input style={{ ...inputStyle, textAlign: "center", letterSpacing: "0.2em" }}
                  type="text" placeholder="000000" maxLength={6}
                  value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"} />
              </div>
              <div>
                <label style={labelStyle}>NEW PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="Min. 8 characters"
                  value={newPass} onChange={e => setNewPass(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#00d4ff"}
                  onBlur={e => e.target.style.borderColor = "#1a3a5c"}
                  onKeyDown={e => e.key === "Enter" && handleReset()} />
              </div>
              <button className="btn btn-primary" style={{ width: "100%", padding: "12px", fontSize: 14 }}
                onClick={handleReset} disabled={loading}>
                {loading ? <><div className="spinner dark" /> Resetting...</> : "✓ Reset Password"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}