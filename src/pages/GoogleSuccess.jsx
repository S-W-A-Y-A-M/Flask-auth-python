import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

export default function GoogleSuccess({ onLogin }) {
  const navigate = useNavigate();

  useEffect(() => {
    console.log("GoogleSuccess mounted, checking for token...");
    // Extract from URL fragment (#token=...)
    const hash = window.location.hash || "";
    const match = hash.match(/token=([^&]+)/);
    const token = match ? decodeURIComponent(match[1]) : null;

    console.log("Extracted token from URL:", token);

    if (token && token.trim() !== "") {
      try {
        // Store JWT in browser storage
        localStorage.setItem("token", token);
        console.log("Token stored in localStorage");
        // Update App state (sets isLoggedIn = true)
        onLogin?.(token);

        // Delay navigation slightly to let App re-render protected routes
        setTimeout(() => {
          navigate("/protected", { replace: true });
        }, 50);
      } catch (err) {
        console.error("Error storing token:", err);
        navigate("/", { replace: true });
      }
    } else {
      console.warn("No token found in Google OAuth redirect.");
      navigate("/", { replace: true });
    }
  }, [navigate, onLogin]);

  return (
    <div style={{ padding: "20px", textAlign: "center" }}>
      <h2>Logging you in with Google...</h2>
      <p>Please wait while we complete the process.</p>
    </div>
  );
}
