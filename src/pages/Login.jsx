import { useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api";
import { FaEye, FaEyeSlash } from "react-icons/fa";
import { FcGoogle } from "react-icons/fc"; // Google icon

export default function Login({ onLogin }) {
  const [form, setForm] = useState({ email: "", password: "" });
  const [message, setMessage] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  // Email/password login
  const submit = async (e) => {
    e.preventDefault();
    setMessage("");
    try {
      const res = await API.post("/login", form);
      const token = res.data?.token;
      if (typeof token === "string" && token.trim() !== "") {
        localStorage.setItem("token", token);
        onLogin?.(token);
        navigate("/protected");
      } else {
        setMessage("Login failed: No valid token received.");
      }
    } catch (err) {
      setMessage(err.response?.data?.error || "Invalid credentials.");
    }
  };

  // Redirect to backend Google OAuth
  const googleLogin = () => {
    window.location.href = "http://localhost:5000/auth/google";
  };

  return (
    <div className="auth-container">
      <h1>Login</h1>
      <form onSubmit={submit}>
        <input
          className="auth-input"
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
          required
        />

        <div style={{ position: "relative", width: "100%" }}>
  <input
    className="auth-input"
    type={showPassword ? "text" : "password"}
    placeholder="Password"
    value={form.password}
    onChange={(e) => setForm({ ...form, password: e.target.value })}
    required
    style={{
      width: "100%",
      paddingRight: "36px",        // Add space for the icon!
      boxSizing: "border-box"
    }}
  />
  <button
    type="button"
    onClick={() => setShowPassword(!showPassword)}
    style={{
      position: "absolute",
      right: "10px",
      top: "50%",
      transform: "translateY(-50%)", // <-- vertical center!
      background: "none",
      border: "none",
      padding: 0,
      margin: 0,
      cursor: "pointer",
      color: "#2563eb",
      fontSize: "18px",
      display: "flex",
      alignItems: "center",
      justifyContent: "center"
    }}
    aria-label={showPassword ? "Hide password" : "Show password"}
  >
    {showPassword ? <FaEyeSlash /> : <FaEye />}
  </button>
</div>


        {message && <p className="error" style={{ color: "red" }}>{message}</p>}

        <button type="submit" className="auth-btn">
          Login
        </button>
      </form>

      <div style={{ textAlign: "center", margin: "15px 0", fontSize: "14px", color: "#888" }}>
        — or —
      </div>

<button
  type="button"
  onClick={googleLogin}
  className="google-btn"
  style={{
    width: "100%",
    padding: "10px",
    background: "#fff",
    border: "1px solid #ccc",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "10px", // Increased gap for clarity
    cursor: "pointer",
    fontSize: "16px",
    color: "#222", // <-- Make sure text color is dark and visible!
    fontWeight: 500
  }}
>
  <FcGoogle size={22} />
  <span style={{ color: "#222", fontWeight: 500 }}>
    Continue with Google
  </span>
</button>
      <style jsx>{`
  .google-btn {
    width: 100%;
    padding: 10px;
    margin-bottom: 6px;
    background: #fff;
    border: 1px solid #ccc;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    cursor: pointer;
    font-size: 16px;
    color: #222 !important;
    font-weight: 500;
    box-sizing: border-box;
    border-radius: 4px;
  }

  .google-btn span {
    color: #222;
    font-weight: 500;
    letter-spacing: 0.05em;
  }

  .auth-input {
    width: 100%;
    padding: 10px;
    padding-right: 36px; /* for password icon */
    margin-bottom: 10px;
    font-size: 16px;
    box-sizing: border-box;
    border: 1px solid #ccc;
    border-radius: 4px;
    outline: none;
  }
  .auth-input:focus {
    border-color: #2563eb;
  }
`}</style>
    </div>
  );
}
