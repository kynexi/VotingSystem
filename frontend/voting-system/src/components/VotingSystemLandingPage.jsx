import { useState } from "react";
import coatOfArms from "../assets/coat.svg";
import {
  Shield,
  Lock,
  CheckCircle,
  Users,
  Server,
  History,
  ArrowRight,
  Globe,
  Key,
  AlertCircle,
  ChevronDown,
} from "lucide-react";

export default function MoldovaVotingSystemLandingPage() {
  const [activeFaq, setActiveFaq] = useState(null);
  const [language, setLanguage] = useState("en");

  const toggleFaq = (index) => {
    setActiveFaq(activeFaq === index ? null : index);
  };

  const features = [
    {
      icon: <Lock className="h-8 w-8 text-red-700" />,
      title: "Secure Authentication",
      description:
        "Multi-factor authentication ensures only eligible Moldovan citizens can access the system.",
    },
    {
      icon: <Shield className="h-8 w-8 text-red-700" />,
      title: "End-to-End Encryption",
      description:
        "All voter data and ballots are encrypted to maintain confidentiality and integrity.",
    },
    {
      icon: <CheckCircle className="h-8 w-8 text-red-700" />,
      title: "Vote Verification",
      description:
        "Voters can verify their votes were counted correctly without compromising anonymity.",
    },
    {
      icon: <Server className="h-8 w-8 text-red-700" />,
      title: "Distributed Systems",
      description:
        "Redundant infrastructure ensures system availability throughout the election period.",
    },
    {
      icon: <Globe className="h-8 w-8 text-red-700" />,
      title: "Multi-Platform Access",
      description:
        "Vote securely from any device with our responsive web and mobile applications.",
    },
    {
      icon: <Users className="h-8 w-8 text-red-700" />,
      title: "Physical Vote Integration",
      description:
        "Seamless integration with traditional voting methods for comprehensive election management.",
    },
  ];

  const faqs = [
    {
      question: "How does the system prevent voter fraud?",
      answer:
        "Our system employs multiple layers of security including biometric verification, unique voter IDs, blockchain technology for immutable records, and real-time monitoring to detect suspicious activities. Each vote is cryptographically secured and verified according to Republic of Moldova electoral standards.",
    },
    {
      question: "What happens if I lose access to my account?",
      answer:
        "We provide several account recovery options, including IDNP (Moldovan personal ID) verification, security questions, and a trusted contact system. Contact your local electoral authority or the CEC (Central Electoral Commission) for immediate assistance.",
    },
    {
      question: "How is my personal data protected?",
      answer:
        "All personal data is encrypted and stored in compliance with Moldova's data protection laws and European standards. Your voting choices are separated from your identity through a cryptographic process that maintains anonymity while ensuring vote integrity.",
    },
    {
      question: "Can I vote from abroad?",
      answer:
        "Yes, Moldovan citizens living abroad can access the system from any location. Our security measures ensure that each eligible voter can only cast one vote per election while providing accessible voting options for our diaspora.",
    },
    {
      question: "How are votes counted and verified?",
      answer:
        "Votes are automatically tabulated by our secure system, with multiple independent verification processes. The Central Electoral Commission of Moldova, independent auditors, and authorized observers can verify the integrity of the count without compromising voter privacy.",
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header/Navigation */}
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
            <nav className="hidden md:flex space-x-8">
              <a href="#features" className="hover:text-yellow-300 transition">
                Features
              </a>
              <a href="#security" className="hover:text-yellow-300 transition">
                Security
              </a>
              <a
                href="#how-it-works"
                className="hover:text-yellow-300 transition"
              >
                How It Works
              </a>
              <a href="#faq" className="hover:text-yellow-300 transition">
                FAQ
              </a>
            </nav>
            <div className="flex space-x-4 items-center">
              <div className="relative">
                <button className="flex items-center text-sm hover:text-yellow-300 transition">
                  <Globe className="h-4 w-4 mr-1" />
                  English
                  <ChevronDown className="h-4 w-4 ml-1" />
                </button>
                {/* Language dropdown would go here */}
              </div>
              <a
                href="/login"
                className="px-4 py-2 text-blue-900 bg-white rounded hover:bg-blue-100 transition"
              >
                Login
              </a>
              <a
                href="/register"
                className="px-4 py-2 border border-yellow-400 bg-red-700 rounded hover:bg-red-800 transition"
              >
                Register
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="bg-gradient-to-r from-blue-800 via-blue-700 to-red-700 text-white py-20 border-b-4 border-yellow-400">
        <div className="container mx-auto px-4 text-center">
          <div className="flex justify-center mb-6">
            <img
              src={coatOfArms}
              alt="Coat of Arms of Moldova"
              className="h-20"
            />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold mb-6">
            Official Digital Voting System of the Republic of Moldova
          </h1>
          <p className="text-xl md:text-2xl max-w-3xl mx-auto mb-10">
            A secure, transparent, and accessible platform ensuring democratic
            participation for all eligible Moldovan citizens, at home and
            abroad.
          </p>
          <div className="flex flex-col md:flex-row justify-center gap-4">
            <a
              href="/register"
              className="bg-yellow-400 text-blue-900 px-8 py-3 rounded-lg font-bold hover:bg-yellow-300 transition flex items-center justify-center"
            >
              Register to Vote <ArrowRight className="ml-2 h-5 w-5" />
            </a>
            <a
              href="/learn-more"
              className="border border-white px-8 py-3 rounded-lg font-bold hover:bg-blue-700 transition flex items-center justify-center"
            >
              Learn More
            </a>
          </div>
        </div>
      </section>

      {/* Key Features */}
      <section id="features" className="py-16 bg-white">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-12">
            Secure Voting Infrastructure
          </h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <div
                key={index}
                className="bg-gray-50 p-6 rounded-lg border border-gray-200 hover:shadow-md transition"
              >
                <div className="mb-4">{feature.icon}</div>
                <h3 className="text-xl font-bold mb-2">{feature.title}</h3>
                <p className="text-gray-600">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section id="security" className="py-16 bg-gray-100">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center gap-12">
            <div className="md:w-1/2">
              <h2 className="text-3xl font-bold mb-6">
                Maximum Security Standards
              </h2>
              <p className="text-lg text-gray-700 mb-6">
                Moldova's E-Vot system implements the highest level of security
                measures to ensure the integrity of every election:
              </p>
              <ul className="space-y-4">
                <li className="flex items-start">
                  <Key className="h-6 w-6 text-red-700 mr-2 mt-1" />
                  <span>
                    End-to-end encryption protects voter data and ballot
                    selections
                  </span>
                </li>
                <li className="flex items-start">
                  <Lock className="h-6 w-6 text-red-700 mr-2 mt-1" />
                  <span>
                    Multi-factor authentication prevents unauthorized access
                  </span>
                </li>
                <li className="flex items-start">
                  <Shield className="h-6 w-6 text-red-700 mr-2 mt-1" />
                  <span>
                    Immutable audit trails ensure transparency and verifiability
                  </span>
                </li>
                <li className="flex items-start">
                  <AlertCircle className="h-6 w-6 text-red-700 mr-2 mt-1" />
                  <span>Real-time threat monitoring and anomaly detection</span>
                </li>
              </ul>
            </div>
            <div className="md:w-1/2 bg-white p-8 rounded-lg shadow-lg border border-gray-200">
              <h3 className="text-2xl font-bold mb-4 text-red-700">
                Security Certifications
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="border border-gray-200 rounded p-4 flex items-center justify-center">
                  <p className="font-bold text-center">ISO 27001</p>
                </div>
                <div className="border border-gray-200 rounded p-4 flex items-center justify-center">
                  <p className="font-bold text-center">
                    EU Standards Compliant
                  </p>
                </div>
                <div className="border border-gray-200 rounded p-4 flex items-center justify-center">
                  <p className="font-bold text-center">SOC 2 Type II</p>
                </div>
                <div className="border border-gray-200 rounded p-4 flex items-center justify-center">
                  <p className="font-bold text-center">GDPR Compliant</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="py-16 bg-white">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-12">How It Works</h2>
          <div className="max-w-4xl mx-auto">
            <div className="flex flex-col md:flex-row items-center mb-12">
              <div className="md:w-1/2 mb-6 md:mb-0 md:pr-8">
                <div className="bg-blue-100 h-64 rounded-lg flex items-center justify-center">
                  <Users className="h-24 w-24 text-blue-600" />
                </div>
              </div>
              <div className="md:w-1/2">
                <h3 className="text-2xl font-bold mb-4">
                  1. Secure Registration
                </h3>
                <p className="text-gray-700">
                  Create your secure voter account using your IDNP (Moldovan ID
                  number) verification. Our system ensures only eligible
                  Moldovan citizens can register while protecting your personal
                  information.
                </p>
              </div>
            </div>

            <div className="flex flex-col md:flex-row-reverse items-center mb-12">
              <div className="md:w-1/2 mb-6 md:mb-0 md:pl-8">
                <div className="bg-yellow-100 h-64 rounded-lg flex items-center justify-center">
                  <Lock className="h-24 w-24 text-yellow-600" />
                </div>
              </div>
              <div className="md:w-1/2">
                <h3 className="text-2xl font-bold mb-4">
                  2. Authenticated Access
                </h3>
                <p className="text-gray-700">
                  Log in securely using multi-factor authentication. Access your
                  personalized voter portal from any device while maintaining
                  the highest security standards, whether you're in Moldova or
                  abroad.
                </p>
              </div>
            </div>

            <div className="flex flex-col md:flex-row items-center">
              <div className="md:w-1/2 mb-6 md:mb-0 md:pr-8">
                <div className="bg-red-100 h-64 rounded-lg flex items-center justify-center">
                  <CheckCircle className="h-24 w-24 text-red-600" />
                </div>
              </div>
              <div className="md:w-1/2">
                <h3 className="text-2xl font-bold mb-4">
                  3. Secure Voting Process
                </h3>
                <p className="text-gray-700">
                  Cast your ballot with confidence. Each vote is encrypted,
                  anonymized, and securely recorded according to Moldovan
                  electoral law. Receive a verification receipt to confirm your
                  vote was counted correctly.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-16 bg-gray-100">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-12">
            Frequently Asked Questions
          </h2>
          <div className="max-w-3xl mx-auto">
            {faqs.map((faq, index) => (
              <div key={index} className="mb-4">
                <button
                  className="flex justify-between items-center w-full p-4 bg-white rounded-lg shadow-sm border border-gray-200 hover:bg-gray-50 transition"
                  onClick={() => toggleFaq(index)}
                >
                  <span className="font-bold text-left">{faq.question}</span>
                  <span className="text-red-700">
                    {activeFaq === index ? "-" : "+"}
                  </span>
                </button>
                {activeFaq === index && (
                  <div className="p-4 bg-gray-50 rounded-b-lg border-t-0 border border-gray-200">
                    <p className="text-gray-700">{faq.answer}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 bg-gradient-to-r from-blue-800 to-red-700 text-white border-t-4 border-yellow-400">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-3xl font-bold mb-6">
            Ready to Experience Moldova's Secure Digital Voting?
          </h2>
          <p className="text-xl max-w-2xl mx-auto mb-8">
            Join fellow Moldovan citizens who trust our platform for secure and
            convenient democratic participation.
          </p>
          <div className="flex flex-col md:flex-row justify-center gap-4">
            <a
              href="/register"
              className="bg-yellow-400 text-blue-900 px-8 py-3 rounded-lg font-bold hover:bg-yellow-300 transition"
            >
              Register Now
            </a>
            <a
              href="/contact"
              className="border border-white px-8 py-3 rounded-lg font-bold hover:bg-blue-700 transition"
            >
              Contact Support
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-blue-900 text-white py-12 border-t-4 border-yellow-400">
        <div className="container mx-auto px-4">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <h3 className="text-xl font-bold mb-4">E-Vot Moldova</h3>
              <p className="text-blue-200">
                The official digital voting system of the Republic of Moldova,
                enabling secure and accessible democratic participation.
              </p>
            </div>
            <div>
              <h4 className="font-bold mb-4">Quick Links</h4>
              <ul className="space-y-2">
                <li>
                  <a
                    href="#features"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    Features
                  </a>
                </li>
                <li>
                  <a
                    href="#security"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    Security
                  </a>
                </li>
                <li>
                  <a
                    href="#how-it-works"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    How It Works
                  </a>
                </li>
                <li>
                  <a
                    href="#faq"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    FAQ
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h4 className="font-bold mb-4">Resources</h4>
              <ul className="space-y-2">
                <li>
                  <a
                    href="/help"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    Help Center
                  </a>
                </li>
                <li>
                  <a
                    href="/documentation"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="/privacy"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    Privacy Policy
                  </a>
                </li>
                <li>
                  <a
                    href="/terms"
                    className="text-blue-200 hover:text-yellow-300 transition"
                  >
                    Terms of Service
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h4 className="font-bold mb-4">Contact</h4>
              <ul className="space-y-2">
                <li className="text-blue-200">Email: support@evot.gov.md</li>
                <li className="text-blue-200">Phone: 0-800-VOTARE</li>
                <li className="text-blue-200">Hours: 24/7 Support</li>
              </ul>
            </div>
          </div>
          <div className="border-t border-blue-800 mt-8 pt-8 text-center text-blue-300">
            <p>
              © {new Date().getFullYear()} Republic of Moldova Central Electoral
              Commission. All rights reserved. Official Government Digital
              Voting Solution.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
