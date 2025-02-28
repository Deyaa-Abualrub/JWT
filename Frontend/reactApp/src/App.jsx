import { useState } from "react";
import axios from "axios";
function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post(
        "http://localhost:3001/register",
        {
          username,
          password,
        },
        { withCredentials: true }
      );
      setMessage(response.data.message);
    } catch (error) {
      setMessage(error.response.data.message);
    }
  };

  const handleAccessProtected = async () => {
    try {
      const response = await axios.get("http://localhost:3001/protected", {
        withCredentials: true,
      });
      setMessage(response.data.message);
    } catch (error) {
      setMessage(error.response.data.message);
    }
  };

  const handleLogout = async () => {
    try {
      await axios.post(
        "http://localhost:3001/logout",
        {},
        { withCredentials: true }
      );
      setMessage("Logged out successfully");
      setIsAuthenticated(false);
    } catch (error) {
      setMessage("Error during logout");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(
        "http://localhost:3001/login",
        { username, password },
        { withCredentials: true }
      );
      setMessage(response.data.message);
      setIsAuthenticated(true);
    } catch (error) {
      setMessage(error.response.data.message);
    }
  };
  return (
    <div>
      <h1>JWT Authentication with Cookies</h1>

      {!isAuthenticated ? (
        <div>
          <h2>Register</h2>
          <form onSubmit={handleRegister}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Register</button>
          </form>

          <h2>Login</h2>
          <form onSubmit={handleLogin}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Login</button>
          </form>
        </div>
      ) : (
        <div>
          <h2>Access Protected Route</h2>
          <button onClick={handleAccessProtected}>Go to Protected Route</button>
          <button onClick={handleLogout}>Logout</button>
        </div>
      )}

      <h3>{message}</h3>
    </div>
  );
}
export default App;
