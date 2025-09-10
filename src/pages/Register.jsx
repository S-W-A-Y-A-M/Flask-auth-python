import { useState } from "react";
import { useNavigate } from "react-router-dom"; // ✅ so we can redirect after register
import API from "../api";
import { FaEye, FaEyeSlash } from "react-icons/fa";

export default function Register({ onRegister }) {
  const [form, setForm] = useState({ email: "", password: "", name: "" });
  const [message, setMessage] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [emailError, setEmailError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validatePassword = (password) => {
    if (password.length < 8) {
      return "Password must be at least 8 characters long.";
    }
    if (!/[A-Z]/.test(password)) {
      return "Password must contain at least one uppercase letter.";
    }
    return "";
  };

  const submit = async (e) => {
    e.preventDefault();

    // Email validation
    if (!validateEmail(form.email)) {
      setEmailError("Please enter a valid email address.");
      return;
    } else {
      setEmailError("");
    }

    // Password validation
    const error = validatePassword(form.password);
    if (error) {
      setPasswordError(error);
      return;
    } else {
      setPasswordError("");
    }

    try {
      const res = await API.post("/register", form);
      const token = res.data?.token;

      if (typeof token === "string" && token.trim() !== "") {
        localStorage.setItem("token", token);   // ✅ persist token
        onRegister?.(token);                    // ✅ update App state instantly
        navigate("/protected");                 // ✅ go to protected route
      } else {
        setMessage("Registered, but no token received.");
      }
    } catch (err) {
      setMessage(err.response?.data?.error || "Error");
    }
  };

  return (
    <div className="auth-container">
      <h1>Register</h1>
      <form onSubmit={submit}>
        <input
          className="auth-input"
          placeholder="Name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          required
        />
        <input
          className="auth-input"
          placeholder="Email"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
          required
        />
        {emailError && <p style={{ color: "red" }}>{emailError}</p>}

        <div style={{ position: "relative" }}>
          <input
            className="auth-input"
            placeholder="Password"
            type={showPassword ? "text" : "password"}
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />
          <span
            onClick={() => setShowPassword(!showPassword)}
            style={{
              position: "absolute",
              right: "10px",
              top: "50%",
              transform: "translateY(-50%)",
              cursor: "pointer",
              color: "#2563eb",
              fontSize: "18px",
            }}
          >
            {showPassword ? <FaEyeSlash /> : <FaEye />}
          </span>
        </div>

        {passwordError && <p style={{ color: "red" }}>{passwordError}</p>}

        <button type="submit">Register</button>
      </form>

      {message && <p className="message">{message}</p>}

      <style jsx>{`
        .auth-input {
          width: 100%;
          padding: 10px;
          margin-bottom: 10px;
          font-size: 16px;
          box-sizing: border-box;
        }
      `}</style>
    </div>
  );
}
