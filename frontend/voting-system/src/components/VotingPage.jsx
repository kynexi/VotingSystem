import { useState, useEffect } from "react";
import coatOfArms from "../assets/coat.svg";
import { useNavigate } from "react-router-dom";
import CONFIG from "../config";
import {
  Check,
  Shield,
  Lock,
  LogOut,
  ChevronDown,
  Globe,
  ArrowLeft,
  Info,
  AlertCircle,
  Clock,
  Fingerprint,
  UserCheck,
  FileText,
  AlignLeft,
  ChevronRight,
  Eye,
  Vote,
  CheckCircle,
  HelpCircle,
  X,
} from "lucide-react";

export default function VotingPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [activeStep, setActiveStep] = useState("verify");
  const [candidates, setCandidates] = useState([]);
  const [selectedCandidate, setSelectedCandidate] = useState(null);
  const [confirmationCode, setConfirmationCode] = useState("");
  const [countdown, setCountdown] = useState(300); // 5 minutes in seconds
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [voter, setVoter] = useState(null);
  const [ballotViewed, setBallotViewed] = useState(false);
  const [voteCast, setVoteCast] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [votingEnabled, setVotingEnabled] = useState(false);
  const [manualVotingEnabled, setManualVotingEnabled] = useState(false);
  const [isWithinElectionPeriod, setIsWithinElectionPeriod] = useState(false);
  const [votingStatus, setVotingStatus] = useState("");
  const [electionStart, setElectionStart] = useState("");
  const [electionEnd, setElectionEnd] = useState("");
  const [electionTimes, setElectionTimes] = useState({
    start: null,
    end: null,
  });
  const navigate = useNavigate();

  // Check if user is authenticated

  const formatDateTime = (date) => {
    if (!date) return "";
    // Format: May 18, 2025 at 14:30
    return new Intl.DateTimeFormat("en-US", {
      month: "long",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  };

  useEffect(() => {
    // Update electionTimes when electionStart and electionEnd change
    if (electionStart && electionEnd) {
      setElectionTimes({
        start: electionStart,
        end: electionEnd,
      });
    }
  }, [electionStart, electionEnd]);

  const fetchElectionInfo = async () => {
    try {
      const res = await fetch("/election-info");
      const data = await res.json();
      if (data.ok) {
        setElectionStart(data.electionStart || "");
        setElectionEnd(data.electionEnd || "");
        setVotingEnabled(data.votingEnabled);

        const now = new Date();
        const startDate = new Date(data.electionStart);
        const endDate = new Date(data.electionEnd);

        if (!data.votingEnabled) {
          setVotingStatus(
            `Voting is currently closed. Voting opens on ${formatDateTime(
              startDate
            )}`
          );
        } else if (now > endDate) {
          setVotingStatus(
            `Voting is closed. Election ended on ${formatDateTime(endDate)}`
          );
        } else {
          setVotingStatus("Voting is open");
        }
      } else {
        setError("Could not fetch election info");
      }
    } catch (err) {
      console.error("Error fetching election info:", err);
      setError("Could not fetch election info");
    }
  };

  useEffect(() => {
    fetchElectionInfo();
  }, []);

  useEffect(() => {
    const token = localStorage.getItem(CONFIG.TOKEN_KEY);
    if (!token) {
      navigate("/login");
      return;
    }

    fetchVoterInfo(token);
  }, [navigate]);

  useEffect(() => {
    if (voter?.isAdmin) {
      fetchElectionSettings(); // only if user is admin
    } else {
      fetchCandidates(); // Fetch election info for all users
    }
  }, [voter]);

  const fetchCandidates = async () => {
    try {
      const res = await fetch(`/candidates`);
      const data = await res.json();
      if (!data.ok) throw new Error("Failed to load candidates");
      setCandidates(data.candidates || []);
    } catch (err) {
      console.error("Candidate fetch error:", err);
      setError("Failed to load candidates");
    }
  };

  // Countdown timer for session
  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    } else if (countdown === 0 && !voteCast) {
      handleTimeout();
    }
  }, [countdown, voteCast]);

  const fetchVoterInfo = async (token) => {
    setLoading(true);
    try {
      const res = await fetch(`/status`, {
        // Add API_URL
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "Failed to fetch voter info");

      setVoter({
        id: data.user_id,
        name: data.name || "Unknown",
        idnp: data.user,
        district: data.voting_area || "Not assigned",
        hasVoted: data.has_voted,
        registeredDevice: data.user_ip,
        isAdmin: data.is_admin,
        lastLogin: new Date().toLocaleString(),
      });
    } catch (err) {
      console.error("Fetch error:", err);
      setError(err.message);
      if (err.message?.includes("Invalid or expired token")) {
        localStorage.removeItem(CONFIG.TOKEN_KEY);
        navigate("/login");
      }
    } finally {
      setLoading(false);
    }
  };

  const fetchElectionSettings = async () => {
    const token = localStorage.getItem(CONFIG.TOKEN_KEY);
    try {
      const res = await fetch(`/admin/election-settings`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (!data.ok)
        throw new Error(data.error || "Failed to fetch election settings");
      setCandidates(data.candidates || []);
    } catch (err) {
      console.error("Election settings fetch error:", err);
      setError("Failed to load election settings");
    }
  };

  // const fetchCandidates = async () => {
  //   const token = localStorage.getItem(CONFIG.TOKEN_KEY);
  //   try {
  //     const res = await fetch(`/admin/election-settings`, {
  //       // Add API_URL
  //       headers: {
  //         Authorization: `Bearer ${token}`,
  //         "Content-Type": "application/json",
  //       },
  //     });
  //     const data = await res.json();
  //     if (!data.ok) throw new Error(data.error || "Failed to fetch candidates");
  //     setCandidates(data.candidates || []);
  //   } catch (err) {
  //     console.error("Candidate fetch error:", err);
  //     setError(err.message);
  //   }
  // };

  const handleVerificationStep = () => {
    if (!votingEnabled) {
      setError(votingStatus || "Voting is currently closed");
      return;
    }

    // Generate random 6-digit confirmation code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    setConfirmationCode(code);

    // In a real app, send the code to the user's registered device
    console.log("Sending confirmation code:", code);

    setActiveStep("vote");
    setBallotViewed(true);
    // Reset countdown when moving to voting step
    setCountdown(300);
  };

  const handleSelectCandidate = (candidateId) => {
    setSelectedCandidate(candidateId);
  };

  const handleVoteSubmission = () => {
    setShowConfirmation(true);
  };

  const handleConfirmVote = async () => {
    const token = localStorage.getItem(CONFIG.TOKEN_KEY);
    setLoading(true);
    try {
      const res = await fetch(`/vote`, {
        // Add API_URL
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ choice: String(selectedCandidate) }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);
      setVoteCast(true);
      setSuccess("Your vote has been successfully recorded!");
      setActiveStep("success");
      setVoter((v) => ({ ...v, hasVoted: true }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      setShowConfirmation(false);
    }
  };

  const handleTimeout = () => {
    setError(
      "Your session has timed out for security reasons. Please log in again."
    );
    setTimeout(() => {
      localStorage.removeItem(CONFIG.TOKEN_KEY);
      navigate("/login");
    }, 3000);
  };

  const handleLogout = () => {
    localStorage.removeItem(CONFIG.TOKEN_KEY);
    navigate("/login");
  };

  // Format time from seconds to MM:SS
  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes.toString().padStart(2, "0")}:${remainingSeconds
      .toString()
      .padStart(2, "0")}`;
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
              {voter && (
                <div className="text-sm border-l border-blue-700 pl-4">
                  <div className="flex items-center">
                    <UserCheck className="h-4 w-4 mr-1" />
                    <span>{voter.name}</span>
                  </div>
                </div>
              )}
              <button
                onClick={handleLogout}
                className="flex items-center text-sm bg-blue-800 px-3 py-1 rounded hover:bg-blue-700 transition"
              >
                <LogOut className="h-4 w-4 mr-1" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-10">
        {(!votingEnabled || !electionTimes?.start) && (
          <div className="max-w-4xl mx-auto bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6">
            <div className="flex items-center">
              <AlertCircle className="h-5 w-5 mr-2" />
              <p>
                {electionTimes?.start
                  ? `Voting is currently closed. Voting opens on ${new Date(
                      electionTimes.start
                    ).toLocaleString()}`
                  : "Voting is currently closed"}
              </p>
            </div>
          </div>
        )}
        <div className="max-w-4xl mx-auto bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
          {/* Session timer and security info */}
          <div className="bg-blue-50 p-3 border-b border-blue-100 flex justify-between items-center">
            <div className="flex items-center text-blue-800">
              <Shield className="h-5 w-5 mr-2" />
              <span className="text-sm font-medium">Secure voting session</span>
            </div>
            {votingEnabled && (
              <div className="flex items-center">
                <Clock className="h-5 w-5 mr-1 text-blue-800" />
                <span
                  className={`text-sm font-mono ${
                    countdown < 60 ? "text-red-600 font-bold" : "text-blue-800"
                  }`}
                >
                  Session time: {formatTime(countdown)}
                </span>
              </div>
            )}
          </div>

          <div className="p-6">
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6">
                <div className="flex items-center">
                  <AlertCircle className="h-5 w-5 mr-2" />
                  {error}
                </div>
              </div>
            )}

            {success && (
              <div className="bg-green-50 border border-green-200 text-green-700 p-4 rounded-md mb-6">
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 mr-2" />
                  {success}
                </div>
              </div>
            )}

            {/* Voting steps indicator */}
            <div className="mb-8 border-b pb-4">
              <div className="flex justify-between">
                <div
                  className={`flex flex-col items-center ${
                    activeStep === "verify"
                      ? "text-blue-700"
                      : activeStep === "success"
                      ? "text-green-600"
                      : "text-gray-500"
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 ${
                      activeStep === "verify"
                        ? "bg-blue-100 text-blue-700 border-2 border-blue-600"
                        : activeStep === "vote" || activeStep === "success"
                        ? "bg-green-100 text-green-700 border-2 border-green-600"
                        : "bg-gray-100 text-gray-500"
                    }`}
                  >
                    <Fingerprint className="h-5 w-5" />
                  </div>
                  <span className="text-xs font-medium">Verify Identity</span>
                </div>

                <div className="flex-1 pt-5 px-2">
                  <div
                    className={`h-1 ${
                      activeStep === "verify" ? "bg-gray-300" : "bg-green-500"
                    }`}
                  ></div>
                </div>

                <div
                  className={`flex flex-col items-center ${
                    activeStep === "vote"
                      ? "text-blue-700"
                      : activeStep === "success"
                      ? "text-green-600"
                      : "text-gray-500"
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 ${
                      activeStep === "vote"
                        ? "bg-blue-100 text-blue-700 border-2 border-blue-600"
                        : activeStep === "success"
                        ? "bg-green-100 text-green-700 border-2 border-green-600"
                        : "bg-gray-100 text-gray-500"
                    }`}
                  >
                    <Vote className="h-5 w-5" />
                  </div>
                  <span className="text-xs font-medium">Cast Vote</span>
                </div>

                <div className="flex-1 pt-5 px-2">
                  <div
                    className={`h-1 ${
                      activeStep === "success" ? "bg-green-500" : "bg-gray-300"
                    }`}
                  ></div>
                </div>

                <div
                  className={`flex flex-col items-center ${
                    activeStep === "success"
                      ? "text-green-600"
                      : "text-gray-500"
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 ${
                      activeStep === "success"
                        ? "bg-green-100 text-green-700 border-2 border-green-600"
                        : "bg-gray-100 text-gray-500"
                    }`}
                  >
                    <CheckCircle className="h-5 w-5" />
                  </div>
                  <span className="text-xs font-medium">Confirmation</span>
                </div>
              </div>
            </div>

            {/* Step content */}
            {activeStep === "verify" && (
              <div>
                <h2 className="text-xl font-bold text-gray-800 mb-4">
                  Identity Verification
                </h2>

                {voter && (
                  <div className="bg-white border border-gray-200 rounded-lg p-4 mb-6">
                    <h3 className="text-lg font-medium text-gray-800 mb-3">
                      Your Voter Information
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-gray-500">Voter ID</p>
                        <p className="font-medium">{voter.id}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Full Name</p>
                        <p className="font-medium">
                          {voter.name !== "Unknown" ? voter.name : "-"}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">IDNP</p>
                        <p className="font-medium">{voter.idnp}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">
                          Device Verification
                        </p>
                        <p className="font-medium text-green-600 flex items-center">
                          <Check className="h-4 w-4 mr-1" />
                          {voter.registeredDevice}
                        </p>
                      </div>
                      <div className="col-span-2">
                        <p className="text-sm text-gray-500">Voting Status</p>
                        <p
                          className={`font-medium ${
                            voter.hasVoted ? "text-green-600" : "text-blue-600"
                          }`}
                        >
                          {voter.hasVoted
                            ? "Vote Already Cast"
                            : "Eligible to Vote"}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="bg-yellow-50 p-4 rounded-md border border-yellow-200 flex items-start mb-6">
                  <AlertCircle className="h-5 w-5 text-yellow-600 mr-2 mt-0.5" />
                  <p className="text-sm text-yellow-700">
                    Please verify that your information is correct. For security
                    purposes, we'll send a verification code to your registered
                    device before proceeding.
                  </p>
                </div>

                <div>
                  <button
                    onClick={handleVerificationStep}
                    disabled={loading || voter?.hasVoted || !votingEnabled}
                    className={`px-4 py-2 ${
                      voter?.hasVoted || !votingEnabled
                        ? "bg-gray-400 cursor-not-allowed"
                        : loading
                        ? "bg-blue-400"
                        : "bg-blue-700 hover:bg-blue-800"
                    } text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2`}
                  >
                    {loading
                      ? "Processing..."
                      : voter?.hasVoted
                      ? "Already Voted"
                      : !votingEnabled
                      ? "Voting is Closed"
                      : "Verify Identity & Continue"}
                  </button>

                  {voter?.hasVoted && (
                    <p className="text-sm text-red-600 mt-2">
                      Our records indicate you have already cast your vote in
                      this election.
                    </p>
                  )}
                  {!votingEnabled && (
                    <div className="max-w-4xl mx-auto bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6">
                      <div className="flex items-center">
                        <AlertCircle className="h-5 w-5 mr-2" />
                        <p>{votingStatus || "Voting is currently closed"}</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeStep === "vote" && (
              <div>
                <h2 className="text-xl font-bold text-gray-800 mb-4">
                  Official Ballot
                </h2>

                <div className="bg-yellow-50 p-4 rounded-md border border-yellow-200 flex items-start mb-6">
                  <Info className="h-5 w-5 text-yellow-600 mr-2 mt-0.5" />
                  <div>
                    <p className="text-sm text-yellow-700 mb-1">
                      Your verification code:{" "}
                      <span className="font-bold">{confirmationCode}</span>
                    </p>
                    <p className="text-sm text-yellow-700">
                      This code has been sent to your registered device. Please
                      keep it for reference.
                    </p>
                  </div>
                </div>

                <div className="border border-gray-300 rounded-lg mb-6">
                  <div className="bg-gray-100 p-4 border-b border-gray-300">
                    <h3 className="text-lg font-medium text-gray-800">
                      Presidential Election 2025
                    </h3>
                    <p className="text-sm text-gray-600">Republic of Moldova</p>
                  </div>

                  <div className="p-4">
                    <p className="text-sm text-gray-700 mb-4">
                      Please select ONE candidate by clicking on their name.
                      Your choice will be highlighted.
                    </p>

                    <div className="space-y-2">
                      {candidates.map((candidate) => (
                        <div
                          key={candidate.id}
                          onClick={() => handleSelectCandidate(candidate.id)}
                          className={`border p-3 rounded-md cursor-pointer transition ${
                            selectedCandidate === candidate.id
                              ? "border-blue-500 bg-blue-50"
                              : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                          }`}
                        >
                          <div className="flex items-center">
                            <div
                              className={`w-6 h-6 border rounded-full mr-3 flex items-center justify-center ${
                                selectedCandidate === candidate.id
                                  ? "border-blue-600 bg-blue-600 text-white"
                                  : "border-gray-400"
                              }`}
                            >
                              {selectedCandidate === candidate.id && (
                                <Check className="h-4 w-4" />
                              )}
                            </div>
                            <div>
                              <h4 className="font-medium">{candidate.name}</h4>
                              <p className="text-sm text-gray-600">
                                {candidate.party}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="flex justify-between">
                  <button
                    onClick={() => setActiveStep("verify")}
                    className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-offset-2"
                  >
                    Back
                  </button>

                  <button
                    onClick={handleVoteSubmission}
                    disabled={!selectedCandidate || loading}
                    className={`px-4 py-2 ${
                      !selectedCandidate
                        ? "bg-gray-400"
                        : loading
                        ? "bg-blue-400"
                        : "bg-blue-700 hover:bg-blue-800"
                    } text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2`}
                  >
                    {loading ? "Processing..." : "Submit Ballot"}
                  </button>
                </div>

                <button
                  onClick={() => setShowHelp(!showHelp)}
                  className="mt-4 text-sm text-blue-600 hover:underline flex items-center"
                >
                  <HelpCircle className="h-4 w-4 mr-1" />
                  {showHelp ? "Hide voting help" : "Need help with voting?"}
                </button>

                {showHelp && (
                  <div className="mt-2 bg-blue-50 p-4 rounded border border-blue-100 text-sm text-blue-800">
                    <h4 className="font-medium mb-2">Voting Instructions:</h4>
                    <ul className="list-disc pl-5 space-y-1">
                      <li>
                        Click on the candidate of your choice to select them
                      </li>
                      <li>Verify your selection is highlighted in blue</li>
                      <li>
                        Click "Submit Ballot" when you are ready to cast your
                        vote
                      </li>
                      <li>
                        You will have a chance to confirm your selection before
                        your vote is final
                      </li>
                      <li>
                        For technical issues, call the support hotline:
                        0-800-VOTARE
                      </li>
                    </ul>
                  </div>
                )}
              </div>
            )}

            {activeStep === "success" && (
              <div className="text-center py-6">
                <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
                <h2 className="text-xl font-bold text-gray-800 mb-2">
                  Vote Successfully Cast
                </h2>
                <p className="text-gray-600 mb-6">
                  Thank you for participating in the democratic process.
                </p>
                <button
                  onClick={handleLogout}
                  className="px-4 py-2 bg-blue-700 text-white rounded-md hover:bg-blue-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                >
                  Exit Voting System
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Information Box */}
        <div className="max-w-4xl mx-auto mt-8 bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
          <div className="bg-blue-800 p-4 border-b-4 border-yellow-400">
            <h2 className="text-lg font-bold text-white">
              Voting System Information
            </h2>
          </div>

          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <div className="flex items-start mb-4">
                  <div className="bg-blue-100 p-2 rounded-full mr-3">
                    <Shield className="h-5 w-5 text-blue-700" />
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-800 mb-1">
                      Security Measures
                    </h3>
                    <p className="text-sm text-gray-600">
                      Our system uses end-to-end encryption, multi-factor
                      authentication, and blockchain technology to ensure secure
                      and transparent voting.
                    </p>
                  </div>
                </div>

                <div className="flex items-start mb-4">
                  <div className="bg-blue-100 p-2 rounded-full mr-3">
                    <Fingerprint className="h-5 w-5 text-blue-700" />
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-800 mb-1">
                      Anti-Fraud Protection
                    </h3>
                    <p className="text-sm text-gray-600">
                      Identity verification, device fingerprinting, and
                      real-time monitoring prevent duplicate voting and
                      unauthorized access.
                    </p>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-start mb-4">
                  <div className="bg-blue-100 p-2 rounded-full mr-3">
                    <Lock className="h-5 w-5 text-blue-700" />
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-800 mb-1">
                      Data Protection
                    </h3>
                    <p className="text-sm text-gray-600">
                      Personal voter data is encrypted and anonymized. Vote
                      choices cannot be linked back to individual voters in the
                      central database.
                    </p>
                  </div>
                </div>

                <div className="flex items-start">
                  <div className="bg-blue-100 p-2 rounded-full mr-3">
                    <FileText className="h-5 w-5 text-blue-700" />
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-800 mb-1">
                      Auditing & Transparency
                    </h3>
                    <p className="text-sm text-gray-600">
                      All voting transactions are logged in a secure, immutable
                      ledger that can be audited without compromising voter
                      privacy.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmation && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-lg max-w-md w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold text-gray-800">
                Confirm Your Vote
              </h3>
              <button
                onClick={() => setShowConfirmation(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="bg-yellow-50 p-4 rounded-md border border-yellow-200 mb-4">
              <p className="text-sm text-yellow-700">
                <span className="font-medium">Important:</span> Your vote is
                about to be submitted. Once confirmed, it cannot be changed.
              </p>
            </div>

            {selectedCandidate &&
              candidates.find((c) => c.id === selectedCandidate) && (
                <div className="border border-gray-200 rounded-lg p-4 mb-4">
                  <p className="text-sm text-gray-500 mb-2">
                    You have selected:
                  </p>
                  <h4 className="font-medium text-gray-800">
                    {candidates.find((c) => c.id === selectedCandidate).name}
                  </h4>
                  <p className="text-sm text-gray-600">
                    {candidates.find((c) => c.id === selectedCandidate).party}
                  </p>
                </div>
              )}

            <div className="flex space-x-3 justify-end">
              <button
                onClick={() => setShowConfirmation(false)}
                className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
              >
                Go Back
              </button>
              <button
                onClick={handleConfirmVote}
                disabled={loading}
                className={`px-4 py-2 ${
                  loading ? "bg-green-400" : "bg-green-600 hover:bg-green-700"
                } text-white rounded-md`}
              >
                {loading ? "Processing..." : "Confirm and Submit Vote"}
              </button>
            </div>
          </div>
        </div>
      )}

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
                href="/help"
                className="text-blue-200 hover:text-yellow-300 transition"
              >
                Help
              </a>
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

          {/* Admin features for physical voting data processing */}
          {voter?.isAdmin && (
            <div className="mt-6 pt-6 border-t border-blue-800">
              <h3 className="text-lg font-medium text-white mb-3">
                Electoral Administration Tools
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <a
                  href="/admin/physical-votes"
                  className="bg-blue-800 hover:bg-blue-700 transition p-3 rounded-md flex items-center"
                >
                  <FileText className="h-5 w-5 mr-2" />
                  <span>Process Physical Ballots</span>
                </a>
                <a
                  href="/admin/statistics"
                  className="bg-blue-800 hover:bg-blue-700 transition p-3 rounded-md flex items-center"
                >
                  <AlignLeft className="h-5 w-5 mr-2" />
                  <span>Election Statistics</span>
                </a>
                <a
                  href="/admin/verification"
                  className="bg-blue-800 hover:bg-blue-700 transition p-3 rounded-md flex items-center"
                >
                  <CheckCircle className="h-5 w-5 mr-2" />
                  <span>Verify Results</span>
                </a>
              </div>
            </div>
          )}
        </div>
      </footer>
    </div>
  );
}
