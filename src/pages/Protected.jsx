import { useState, useEffect } from "react";
import API from "../api";

export default function Protected() {
  const [data, setData] = useState("Loading...");

  useEffect(() => {
    const token = localStorage.getItem("token");

    if (!token) {
      setData("Unauthorized: No token found.");
      return;
    }

    API.get("/protected", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => setData(res.data.message || "Success"))
      .catch(() => setData("Unauthorized"));
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-xl">Protected Route</h1>
      <p>{data}</p>
    </div>
  );
}