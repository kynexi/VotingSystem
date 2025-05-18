import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import CONFIG from "../config";
import coatOfArms from "../assets/coat.svg";
import {
  Users,
  FileBarChart,
  Settings,
  LogOut,
  ChevronDown,
  Globe,
  Search,
  Bell,
  AlertCircle,
  CheckCircle,
  Trash,
  Edit,
  Filter,
} from "lucide-react";

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState("users");
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [loadingStats, setLoadingStats] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [candidates, setCandidates] = useState([]);
  const [electionStart, setElectionStart] = useState("");
  const [electionEnd, setElectionEnd] = useState("");
  const [votingEnabled, setVotingEnabled] = useState(false);
  const [stats, setStats] = useState(null);
  const navigate = useNavigate();

  // On tab change, clear messages and fetch data.
  useEffect(() => {
    setError("");
    setSuccess("");
    if (activeTab === "users") {
      fetchUsers();
    } else if (activeTab === "elections") {
      fetchElectionSettings();
    } else if (activeTab === "statistics") {
      fetchStats();
    }
  }, [activeTab]);

  // Helper: if API response indicates the user isn’t admin, redirect.
  const checkAdminError = (data) => {
    if (
      data.error &&
      data.error.toLowerCase().includes("not an administrator")
    ) {
      navigate("/vote");
    }
  };

  const fetchUsers = async () => {
    setLoadingUsers(true);
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      if (!token) {
        navigate("/login");
        return;
      }
      const res = await fetch("/admin", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (data.ok) {
        setUsers(data.users);
      } else {
        setError(data.error || "Failed to fetch users");
        checkAdminError(data);
      }
    } catch {
      setError("Network error. Please check if the backend server is running.");
    } finally {
      setLoadingUsers(false);
    }
  };

  // FETCH ELECTION SETTINGS (Candidates, Election Times, Voting Status)
  const fetchElectionSettings = async () => {
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch("/admin/election-settings", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (data.ok) {
        setCandidates(data.candidates || []);
        setElectionStart(data.electionStart || "");
        setElectionEnd(data.electionEnd || "");
        setVotingEnabled(data.votingEnabled);
      } else {
        setError(data.error || "Failed to load election settings");
      }
    } catch {
      setError("Failed to load election settings");
    }
  };

  // FETCH STATISTICS
  const fetchStats = async () => {
    setLoadingStats(true);
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch("/results", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (data.ok) {
        // Assume backend returns an object with stats, results, online_votes, physical_votes
        setStats(data);
      } else {
        setError(data.error || "Failed to load statistics");
      }
    } catch {
      setError("Network error fetching statistics");
    } finally {
      setLoadingStats(false);
    }
  };

  // TOGGLE VOTING (simply calls /admin/toggle-voting)
  const handleToggleVoting = async () => {
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch("/admin/toggle-voting", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (data.ok) {
        // Update local votingEnabled based on response message if needed
        setVotingEnabled(!votingEnabled);
        setSuccess(
          data.message || `Voting ${!votingEnabled ? "enabled" : "disabled"}`
        );
      } else {
        setError(data.error || "Failed to update voting status");
      }
    } catch {
      setError("Failed to toggle voting status");
    }
  };

  // UPDATE ELECTION TIMES
  const handleUpdateElectionTimes = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch("/admin/election-times", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ start: electionStart, end: electionEnd }),
      });
      const data = await res.json();
      if (data.ok) {
        setSuccess("Election times updated successfully");
      } else {
        setError(data.error || "Failed to update election times");
      }
    } catch {
      setError("Failed to update election times");
    }
  };

  // ADD NEW CANDIDATE
  const handleAddCandidate = async (e) => {
    e.preventDefault();
    const name = e.target.name.value;
    const party = e.target.party.value;
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch("/admin/candidates", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name, party }),
      });
      const data = await res.json();
      if (data.ok) {
        fetchElectionSettings();
        setSuccess("Candidate added successfully");
        e.target.reset();
      } else {
        setError(data.error || "Failed to add candidate");
      }
    } catch {
      setError("Failed to add candidate");
    }
  };

  // DELETE CANDIDATE
  const handleDeleteCandidate = async (candidateId) => {
    if (!window.confirm("Remove this candidate?")) return;
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch(`/admin/candidates/${candidateId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
      const data = await res.json();
      if (data.ok) {
        fetchElectionSettings();
        setSuccess("Candidate removed");
      } else {
        setError(data.error || "Failed to delete candidate");
      }
    } catch {
      setError("Network error. Could not delete candidate.");
    }
  };

  // DELETE USER
  const handleDeleteUser = async (userId) => {
    if (!window.confirm("Are you sure you want to delete this user?")) return;
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      const res = await fetch(`/admin/users/${userId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (data.ok) {
        setSuccess("User deleted successfully");
        fetchUsers();
      } else {
        setError(data.error || "Failed to delete user");
      }
    } catch {
      setError("Network error. Please check if the backend server is running.");
    }
  };

  // LOGOUT
  const handleLogout = async () => {
    try {
      const token = localStorage.getItem(CONFIG.TOKEN_KEY);
      await fetch("/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch {
      // Ignore errors on logout
    } finally {
      localStorage.removeItem(CONFIG.TOKEN_KEY);
      navigate("/login");
    }
  };

  const filteredUsers = users.filter(
    (u) =>
      u.user?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.email?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* HEADER */}
      <header className="bg-blue-900 text-white border-b-4 border-yellow-400">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center">
            <img src={coatOfArms} alt="CoA" className="h-12 mr-3" />
            <h1 className="text-2xl font-bold">E-Vot Moldova</h1>
          </div>
          <div className="flex space-x-4 items-center">
            <button className="flex items-center text-sm hover:text-yellow-300 transition">
              <Globe className="h-4 w-4 mr-1" /> English
              <ChevronDown className="h-4 w-4 ml-1" />
            </button>
            <button className="text-sm hover:text-yellow-300 transition">
              <Bell className="h-5 w-5" />
            </button>
            <button
              onClick={handleLogout}
              className="flex items-center text-sm hover:text-yellow-300 transition"
            >
              <LogOut className="h-4 w-4 mr-1" /> Logout
            </button>
          </div>
        </div>
      </header>

      {/* TABS */}
      <div className="container mx-auto px-4 py-6">
        <div className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
          <div className="bg-blue-800 p-6 border-b-4 border-yellow-400">
            <h2 className="text-2xl font-bold text-white">
              Administration Panel
            </h2>
            <p className="text-blue-100 mt-2">
              Manage users, view statistics, and configure system settings
            </p>
          </div>
          <div className="flex border-b border-gray-200 bg-gray-50">
            <button
              className={`px-6 py-3 text-sm font-medium flex items-center ${
                activeTab === "users"
                  ? "text-blue-700 border-b-2 border-blue-700 bg-white"
                  : "text-gray-600 hover:text-blue-600 hover:bg-gray-100"
              }`}
              onClick={() => setActiveTab("users")}
            >
              <Users className="h-4 w-4 mr-2" /> Users
            </button>
            <button
              className={`px-6 py-3 text-sm font-medium flex items-center ${
                activeTab === "statistics"
                  ? "text-blue-700 border-b-2 border-blue-700 bg-white"
                  : "text-gray-600 hover:text-blue-600 hover:bg-gray-100"
              }`}
              onClick={() => setActiveTab("statistics")}
            >
              <FileBarChart className="h-4 w-4 mr-2" /> Statistics
            </button>
            <button
              className={`px-6 py-3 text-sm font-medium flex items-center ${
                activeTab === "settings"
                  ? "text-blue-700 border-b-2 border-blue-700 bg-white"
                  : "text-gray-600 hover:text-blue-600 hover:bg-gray-100"
              }`}
              onClick={() => setActiveTab("settings")}
            >
              <Settings className="h-4 w-4 mr-2" /> Settings
            </button>
            <button
              className={`px-6 py-3 text-sm font-medium flex items-center ${
                activeTab === "elections"
                  ? "text-blue-700 border-b-2 border-blue-700 bg-white"
                  : "text-gray-600 hover:text-blue-600 hover:bg-gray-100"
              }`}
              onClick={() => setActiveTab("elections")}
            >
              <FileBarChart className="h-4 w-4 mr-2" /> Elections
            </button>
          </div>

          {/* TAB CONTENT */}
          <div className="p-6">
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6 flex items-center">
                <AlertCircle className="h-5 w-5 mr-2" /> {error}
              </div>
            )}
            {success && (
              <div className="bg-green-50 border border-green-200 text-green-700 p-4 rounded-md mb-6 flex items-center">
                <CheckCircle className="h-5 w-5 mr-2" /> {success}
              </div>
            )}

            {activeTab === "users" && (
              <>
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-xl font-semibold text-gray-800">
                    User Management
                  </h3>
                  <div className="flex space-x-2">
                    <div className="relative">
                      <input
                        type="text"
                        placeholder="Search users..."
                        className="pl-9 pr-4 py-2 border border-gray-300 rounded focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                      />
                      <Search className="h-5 w-5 text-gray-400 absolute left-2 top-2.5" />
                    </div>
                    <button className="bg-blue-700 text-white px-4 py-2 rounded flex items-center hover:bg-blue-800">
                      <Filter className="h-4 w-4 mr-1" /> Filter
                    </button>
                  </div>
                </div>
                {loadingUsers ? (
                  <p className="text-center py-4">Loading users...</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                            User
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                            Email
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {filteredUsers.length > 0 ? (
                          filteredUsers.map((u) => (
                            <tr key={u.id} className="hover:bg-gray-50">
                              <td className="px-6 py-4 whitespace-nowrap">
                                {u.user}
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap">
                                {u.email}
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                <button className="text-blue-600 hover:text-blue-900 mr-3">
                                  <Edit className="h-4 w-4" />
                                </button>
                                <button
                                  className="text-red-600 hover:text-red-900"
                                  onClick={() => handleDeleteUser(u.id)}
                                >
                                  <Trash className="h-4 w-4" />
                                </button>
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td
                              colSpan={3}
                              className="px-6 py-4 text-center text-sm text-gray-500"
                            >
                              No users found
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeTab === "statistics" && (
              <>
                {loadingStats ? (
                  <p className="text-center py-4">Loading statistics…</p>
                ) : stats ? (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                        <h3 className="text-lg font-semibold text-gray-700 mb-2">
                          Total Voters
                        </h3>
                        <p className="text-3xl font-bold text-blue-600">
                          {stats.stats?.total_voters || 0}
                        </p>
                      </div>
                      <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                        <h3 className="text-lg font-semibold text-gray-700 mb-2">
                          Total Votes Cast
                        </h3>
                        <p className="text-3xl font-bold text-green-600">
                          {stats.stats?.total_votes || 0}
                        </p>
                      </div>
                      <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                        <h3 className="text-lg font-semibold text-gray-700 mb-2">
                          Participation Rate
                        </h3>
                        <p className="text-3xl font-bold text-purple-600">
                          {stats.stats?.participation?.toFixed(1) || 0}%
                        </p>
                      </div>
                    </div>
                    <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                      <h3 className="text-lg font-semibold mb-4">
                        Vote Distribution
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-medium mb-2">Total Votes</h4>
                          {stats.results &&
                            Object.entries(stats.results).map(
                              ([choice, count]) => (
                                <div
                                  key={choice}
                                  className="flex justify-between items-center mb-2"
                                >
                                  <span>Option {choice}</span>
                                  <span className="font-bold">{count}</span>
                                </div>
                              )
                            )}
                        </div>
                        <div>
                          <h4 className="font-medium mb-2">
                            Online vs Physical
                          </h4>
                          <div className="space-y-2">
                            {stats.online_votes &&
                              Object.entries(stats.online_votes).map(
                                ([choice, count]) => (
                                  <div
                                    key={`online-${choice}`}
                                    className="flex justify-between items-center"
                                  >
                                    <span>Online - Option {choice}</span>
                                    <span className="font-bold">{count}</span>
                                  </div>
                                )
                              )}
                            {stats.physical_votes &&
                              Object.entries(stats.physical_votes).map(
                                ([choice, count]) => (
                                  <div
                                    key={`physical-${choice}`}
                                    className="flex justify-between items-center"
                                  >
                                    <span>Physical - Option {choice}</span>
                                    <span className="font-bold">{count}</span>
                                  </div>
                                )
                              )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-center text-gray-600">
                    No statistics available.
                  </p>
                )}
              </>
            )}

            {activeTab === "settings" && (
              <p className="text-center text-gray-600">
                Settings module is under development
              </p>
            )}

            {activeTab === "elections" && (
              <div className="space-y-8">
                {/* Voting Status */}
                <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">Voting Status</h3>
                  <button
                    onClick={handleToggleVoting}
                    className={`px-4 py-2 rounded-md text-white ${
                      votingEnabled
                        ? "bg-red-600 hover:bg-red-700"
                        : "bg-green-600 hover:bg-green-700"
                    }`}
                  >
                    {votingEnabled ? "Disable Voting" : "Enable Voting"}
                  </button>
                </div>

                {/* Election Times */}
                <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">
                    Election Time Period
                  </h3>
                  <form
                    onSubmit={handleUpdateElectionTimes}
                    className="space-y-4"
                  >
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Start Time
                        </label>
                        <input
                          type="datetime-local"
                          value={electionStart}
                          onChange={(e) => setElectionStart(e.target.value)}
                          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          End Time
                        </label>
                        <input
                          type="datetime-local"
                          value={electionEnd}
                          onChange={(e) => setElectionEnd(e.target.value)}
                          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                    </div>
                    <button
                      type="submit"
                      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                    >
                      Update Election Times
                    </button>
                  </form>
                </div>

                {/* Manage Candidates */}
                <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">
                    Manage Candidates
                  </h3>
                  <form
                    onSubmit={handleAddCandidate}
                    className="mb-6 space-y-4"
                  >
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Candidate Name
                        </label>
                        <input
                          type="text"
                          name="name"
                          required
                          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Party
                        </label>
                        <input
                          type="text"
                          name="party"
                          required
                          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                    </div>
                    <button
                      type="submit"
                      className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
                    >
                      Add Candidate
                    </button>
                  </form>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                            Name
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                            Party
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {candidates.map((c) => (
                          <tr key={c.id}>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {c.name}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {c.party}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <button
                                onClick={() => handleDeleteCandidate(c.id)}
                                className="text-red-600 hover:text-red-900"
                              >
                                <Trash className="h-5 w-5" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* FOOTER */}
      <footer className="bg-blue-900 text-white py-6 border-t-4 border-yellow-400">
        <div className="container mx-auto px-4 flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center mb-4 md:mb-0">
            <img src={coatOfArms} alt="CoA" className="h-8 mr-2" />
            <p className="text-sm">
              © {new Date().toLocaleDateString("en-GB")} CEC Moldova
            </p>
          </div>
          <div className="flex space-x-4 text-sm">
            <a href="/privacy" className="hover:text-yellow-300">
              Privacy
            </a>
            <a href="/terms" className="hover:text-yellow-300">
              Terms
            </a>
            <a href="/accessibility" className="hover:text-yellow-300">
              Accessibility
            </a>
            <a href="/contact" className="hover:text-yellow-300">
              Contact
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
