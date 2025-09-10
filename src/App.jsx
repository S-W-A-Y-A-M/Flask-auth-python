import { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Link, Navigate, useNavigate } from "react-router-dom";

import Register from "./pages/Register";
import Login from "./pages/Login";
import Protected from "./pages/Protected";
import GoogleSuccess from "./pages/GoogleSuccess";
import "./index.css";

function App() {
  const navigate = useNavigate();
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem("token"));
  const [showLogin, setShowLogin] = useState(true);

  // Reactively update login state on token changes
  useEffect(() => {
    const updateLoginStatus = () => setIsLoggedIn(!!localStorage.getItem("token"));
    window.addEventListener("storage", updateLoginStatus);
    return () => window.removeEventListener("storage", updateLoginStatus);
  }, []);

  const handleLogin = (token) => {
    if (token) {
      localStorage.setItem("token", token);
      setIsLoggedIn(true);
      // ✅ Navigating is now handled inside Login or GoogleSuccess, not here
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    setIsLoggedIn(false);
    setShowLogin(true);
    navigate("/"); // go back home
  };

  return (
    <>
      <nav className="navbar">
        {!isLoggedIn ? (
          <>
            <button
              className={`nav-btn ${showLogin ? "active" : ""}`}
              onClick={() => setShowLogin(true)}
            >
              Login
            </button>
            <button
              className={`nav-btn ${!showLogin ? "active" : ""}`}
              onClick={() => setShowLogin(false)}
            >
              Register
            </button>
          </>
        ) : (
          <>
            <Link className="nav-link" to="/protected">Protected</Link>
            <button className="nav-btn logout" onClick={handleLogout}>
              Logout
            </button>
          </>
        )}
      </nav>

      <div className="page-container">
        <Routes>
          {/* Always available: Google OAuth callback */}
          <Route path="/google-success" element={<GoogleSuccess onLogin={handleLogin} />} />

          {/* Public routes */}
          {!isLoggedIn && (
            <Route
              path="/"
              element={showLogin ? <Login onLogin={handleLogin} /> : <Register onRegister={handleLogin} />}
            />
          )}

          {/* Protected routes */}
          {isLoggedIn && <Route path="/protected" element={<Protected />} />}

          {/* Catch-all redirects */}
          <Route path="*" element={<Navigate to={isLoggedIn ? "/protected" : "/"} />} />
        </Routes>
      </div>
    </>
  );
}

export default function AppWithRouter() {
  return (
    <BrowserRouter>
      <App />
    </BrowserRouter>
  );
}
