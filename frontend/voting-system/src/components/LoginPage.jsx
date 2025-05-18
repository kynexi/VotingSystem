import { useState } from "react";
import coatOfArms from "../assets/coat.svg";
import api from "../api/client";
import { useNavigate } from "react-router-dom";
import CONFIG from "../config";
import {
  Shield,
  Lock,
  User,
  Mail,
  ChevronDown,
  Globe,
  KeyRound,
  ArrowLeft,
  Info,
  Eye,
  EyeOff,
  AlertCircle,
} from "lucide-react";

export default function LoginPage() {
  const [loginMethod, setLoginMethod] = useState("idnp");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      // First check if backend is reachable

      const formData = {
        user: e.target.idnp?.value || e.target.email?.value,
        pass: e.target.password.value,
        captcha: "1234567890123", // Test captcha
      };

      const response = await fetch(`/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(formData),
      });
      //${CONFIG.API_URL}  JSON.stringify
      const data = await response.json();
      console.log("Login response:", data);
      localStorage.setItem(CONFIG.TOKEN_KEY, data.token);

      if (data.ok) {
        setSuccess("Login successful!");
        localStorage.setItem(CONFIG.TOKEN_KEY, data.token);
        navigate("/vote");
      } else {
        setError(data.error || "Login failed");
      }
    } catch (err) {
      console.error("Login error:", err);
      setError("Network error. Please check if the backend server is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-blue-900 text-white border-b-4 border-yellow-400">
        <div className="container mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center">
              <div className="mr-3">
                <img
                  src={coatOfArms}
                  alt="Coat of Arms of Moldova"
                  className="h-12"
                />
              </div>
              <h1 className="text-2xl font-bold">E-Vot Moldova</h1>
            </div>
            <div className="flex space-x-4 items-center">
              <div className="relative">
                <button className="flex items-center text-sm hover:text-yellow-300 transition">
                  <Globe className="h-4 w-4 mr-1" />
                  English
                  <ChevronDown className="h-4 w-4 ml-1" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-10">
        <div className="max-w-md mx-auto bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
          <div className="bg-blue-800 p-6 border-b-4 border-yellow-400">
            <div className="flex items-center mb-4">
              <a
                href="/"
                className="text-white hover:text-yellow-300 flex items-center"
              >
                <ArrowLeft className="h-5 w-5 mr-2" />
                Return to Home
              </a>
            </div>
            <h1 className="text-2xl font-bold text-white">Login to E-Vot</h1>
            <p className="text-blue-100 mt-2">
              Secure access to the official digital voting system of the
              Republic of Moldova
            </p>
          </div>

          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-green-50 border border-green-200 text-green-700 p-4 rounded-md">
                {success}
              </div>
            )}
            <div className="flex border rounded-md overflow-hidden">
              <button
                type="button"
                className={`w-1/2 py-2 text-center text-sm font-medium ${
                  loginMethod === "idnp"
                    ? "bg-blue-50 text-blue-700"
                    : "bg-gray-50 text-gray-700 hover:bg-gray-100"
                }`}
                onClick={() => setLoginMethod("idnp")}
              >
                Login with IDNP
              </button>
              <button
                type="button"
                className={`w-1/2 py-2 text-center text-sm font-medium ${
                  loginMethod === "email"
                    ? "bg-blue-50 text-blue-700"
                    : "bg-gray-50 text-gray-700 hover:bg-gray-100"
                }`}
                onClick={() => setLoginMethod("email")}
              >
                Login with Email
              </button>
            </div>

            {loginMethod === "idnp" ? (
              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="idnp"
                >
                  IDNP (Personal Identification Number)
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="idnp"
                    className="w-full p-2 pl-9 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    placeholder="e.g. 2002004123456"
                    maxLength="13"
                  />
                  <KeyRound className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                </div>
              </div>
            ) : (
              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="email"
                >
                  Email Address
                </label>
                <div className="relative">
                  <input
                    type="email"
                    id="email"
                    className="w-full p-2 pl-9 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    placeholder="email@example.com"
                  />
                  <Mail className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                </div>
              </div>
            )}

            <div>
              <label
                className="block text-sm font-medium text-gray-700 mb-1"
                htmlFor="password"
              >
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  className="w-full p-2 pl-9 pr-10 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  placeholder="Enter your password"
                />
                <Lock className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                <button
                  type="button"
                  className="absolute right-2 top-2.5 text-gray-400 hover:text-gray-600"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5" />
                  ) : (
                    <Eye className="h-5 w-5" />
                  )}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label
                  htmlFor="remember-me"
                  className="ml-2 block text-sm text-gray-700"
                >
                  Remember me
                </label>
              </div>
              <a
                href="/reset-password"
                className="text-sm text-blue-600 hover:underline"
              >
                Forgot password?
              </a>
            </div>

            <div className="bg-yellow-50 p-4 rounded-md border border-yellow-200 flex items-start">
              <AlertCircle className="h-5 w-5 text-yellow-600 mr-2 mt-0.5" />
              <p className="text-sm text-yellow-700">
                For your security, this system uses multi-factor authentication.
                After entering your credentials, you will receive a verification
                code on your registered mobile device.
              </p>
            </div>

            <div>
              <button
                type="submit"
                className="w-full px-4 py-2 bg-red-700 text-white rounded-md hover:bg-red-800 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
              >
                Login
              </button>
            </div>

            <div className="text-center">
              <a
                href="/register"
                className="text-sm text-blue-600 hover:underline"
              >
                Don't have an account? Register here
              </a>
            </div>
          </form>

          <div className="bg-gray-50 p-6 border-t border-gray-200">
            <h3 className="text-sm font-medium text-gray-700 mb-3">
              Login Support
            </h3>
            <div className="flex items-start space-x-2">
              <div className="bg-blue-100 text-blue-800 p-2 rounded-full">
                <Info className="h-5 w-5" />
              </div>
              <div>
                <p className="text-sm text-gray-600 mb-1">
                  Need help logging in? Contact the support center at
                  <span className="font-medium"> 0-800-VOTARE</span> or email
                  <span className="font-medium"> support@evot.gov.md</span>
                </p>
                <p className="text-sm text-gray-600">
                  Available Monday-Friday, 8:00-20:00
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-blue-900 text-white py-6 border-t-4 border-yellow-400 mt-10">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center mb-4 md:mb-0">
              <img
                src={coatOfArms}
                alt="Coat of Arms of Moldova"
                className="h-8 mr-2"
              />
              <p className="text-sm">
                © {new Date().getFullYear()} Republic of Moldova Central
                Electoral Commission
              </p>
            </div>
            <div className="flex space-x-4 text-sm">
              <a
                href="/privacy"
                className="text-blue-200 hover:text-yellow-300 transition"
              >
                Privacy
              </a>
              <a
                href="/terms"
                className="text-blue-200 hover:text-yellow-300 transition"
              >
                Terms
              </a>
              <a
                href="/accessibility"
                className="text-blue-200 hover:text-yellow-300 transition"
              >
                Accessibility
              </a>
              <a
                href="/contact"
                className="text-blue-200 hover:text-yellow-300 transition"
              >
                Contact
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
