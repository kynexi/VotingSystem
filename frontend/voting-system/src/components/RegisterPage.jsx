import { useState } from "react";
import coatOfArms from "../assets/coat.svg";
import { useNavigate } from "react-router-dom";
import CONFIG from "../config";
import {
  Shield,
  Lock,
  User,
  Mail,
  Calendar,
  ChevronDown,
  Globe,
  KeyRound,
  ArrowLeft,
  Info,
  Check,
  Eye,
  EyeOff,
} from "lucide-react";

export default function RegisterPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  // Add these new state variables
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    const formData = {
      user: e.target.idnp.value,
      firstName: e.target.firstName.value,
      lastName: e.target.lastName.value,
      email: e.target.email.value,
      phone: e.target.phone.value,
      pass: e.target.password.value,
      birthdate: e.target.birthdate.value,
      captcha: "1234567890123",
    };

    console.log("Form data:", formData);

    try {
      const response = await fetch(`/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        mode: "cors", // Add this
        body: JSON.stringify(formData),
      });

      console.log("Register response:", response);
      const data = await response.json();
      console.log("Register data:", data);

      if (!response.ok) {
        throw new Error(data.error || "Registration failed");
      }

      if (data.ok) {
        setSuccess("Registration successful! Please save your recovery code.");
        setRecoveryCode(data.recovery_code);
        setTimeout(() => {
          navigate("/login");
        }, 5000);
      } else {
        throw new Error(data.error || "Registration failed");
      }
    } catch (err) {
      console.error("Registration error:", err);
      setError(
        err.message ||
          "Network error. Please check your connection and ensure the backend server is running."
      );
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
        <div className="max-w-3xl mx-auto bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
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
            <h1 className="text-2xl font-bold text-white">
              Citizen Registration
            </h1>
            <p className="text-blue-100 mt-2">
              Register to access the official digital voting system of the
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
                <p>{success}</p>
                {recoveryCode && (
                  <p className="mt-2 font-mono bg-green-100 p-2 rounded">
                    Recovery Code: {recoveryCode}
                  </p>
                )}
                <p className="mt-2 text-sm">
                  Redirecting to login page in 5 seconds...
                </p>
              </div>
            )}
            <div className="bg-yellow-50 p-4 rounded-md border border-yellow-200 flex items-start mb-6">
              <Info className="h-5 w-5 text-yellow-600 mr-2 mt-0.5" />
              <p className="text-sm text-yellow-700">
                To register, you must be a citizen of the Republic of Moldova
                with a valid IDNP (personal identification number). All
                information is verified through the State Population Register.
              </p>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
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
                <p className="text-xs text-gray-500 mt-1">
                  Your 13-digit personal identification number
                </p>
              </div>

              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="birthdate"
                >
                  Date of Birth
                </label>
                <div className="relative">
                  <input
                    type="date"
                    id="birthdate"
                    className="w-full p-2 pl-9 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  />
                  <Calendar className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                </div>
              </div>

              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="firstName"
                >
                  First Name
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="firstName"
                    className="w-full p-2 pl-9 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    placeholder="First Name"
                  />
                  <User className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                </div>
              </div>

              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="lastName"
                >
                  Last Name
                </label>
                <div className="relative">
                  <input
                    type="text"
                    id="lastName"
                    className="w-full p-2 pl-9 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    placeholder="Last Name"
                  />
                  <User className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                </div>
              </div>

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

              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="phone"
                >
                  Phone Number
                </label>
                <div className="relative">
                  <input
                    type="tel"
                    id="phone"
                    className="w-full p-2 pl-9 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    placeholder="+373 XX XXX XXX"
                  />
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-5 w-5 text-gray-400 absolute left-2 top-2.5"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" />
                  </svg>
                </div>
              </div>

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
                    placeholder="Create a secure password"
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
                <p className="text-xs text-gray-500 mt-1">
                  Must be at least 8 characters with letters, numbers, and
                  symbols
                </p>
              </div>

              <div>
                <label
                  className="block text-sm font-medium text-gray-700 mb-1"
                  htmlFor="passwordConfirm"
                >
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showPasswordConfirm ? "text" : "password"}
                    id="passwordConfirm"
                    className="w-full p-2 pl-9 pr-10 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    placeholder="Confirm your password"
                  />
                  <Lock className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                  <button
                    type="button"
                    className="absolute right-2 top-2.5 text-gray-400 hover:text-gray-600"
                    onClick={() => setShowPasswordConfirm(!showPasswordConfirm)}
                  >
                    {showPasswordConfirm ? (
                      <EyeOff className="h-5 w-5" />
                    ) : (
                      <Eye className="h-5 w-5" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-gray-200">
              <div className="flex items-start">
                <div className="flex items-center h-5">
                  <input
                    id="terms"
                    type="checkbox"
                    className="h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                    checked={termsAccepted}
                    onChange={() => setTermsAccepted(!termsAccepted)}
                  />
                </div>
                <div className="ml-3 text-sm">
                  <label htmlFor="terms" className="text-gray-700">
                    I agree to the{" "}
                    <a href="/terms" className="text-blue-600 hover:underline">
                      Terms of Service
                    </a>{" "}
                    and{" "}
                    <a
                      href="/privacy"
                      className="text-blue-600 hover:underline"
                    >
                      Privacy Policy
                    </a>{" "}
                    of the Republic of Moldova E-Voting Platform
                  </label>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between pt-4">
              <a href="/login" className="text-blue-600 hover:underline">
                Already registered? Sign in
              </a>
              <button
                type="submit"
                className={`px-6 py-2 rounded-md font-medium text-white ${
                  termsAccepted
                    ? "bg-red-700 hover:bg-red-800"
                    : "bg-gray-400 cursor-not-allowed"
                }`}
                disabled={!termsAccepted}
              >
                Register
              </button>
            </div>
          </form>

          <div className="bg-gray-50 p-6 border-t border-gray-200">
            <h3 className="text-sm font-medium text-gray-700 mb-3">
              Registration Support
            </h3>
            <div className="flex items-start space-x-2">
              <div className="bg-blue-100 text-blue-800 p-2 rounded-full">
                <Info className="h-5 w-5" />
              </div>
              <p className="text-sm text-gray-600">
                Need help with registration? Contact the support center at{" "}
                <span className="font-medium">0-800-VOTARE</span> or email{" "}
                <span className="font-medium">support@evot.gov.md</span>
              </p>
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
