import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, CheckCircle, Database, Server, Cloud, Lock, ArrowRight, ArrowLeft } from 'lucide-react';
import './App.css';

type Step = 1 | 2 | 3;
type ConnectorType = 'splunk' | 'tenable' | 'aws_security_hub' | 'crowdstrike';

interface ConnectorConfig {
  id: ConnectorType;
  name: string;
  icon: React.ReactNode;
  description: string;
}

const connectors: ConnectorConfig[] = [
  { id: 'splunk', name: 'Splunk', icon: <Database size={32} />, description: 'Enterprise Security & Log Management' },
  { id: 'tenable', name: 'Tenable', icon: <Shield size={32} />, description: 'Vulnerability Management' },
  { id: 'aws_security_hub', name: 'AWS Security Hub', icon: <Cloud size={32} />, description: 'Cloud Security Posture' },
  { id: 'crowdstrike', name: 'CrowdStrike', icon: <Lock size={32} />, description: 'Endpoint Protection' },
];

function App() {
  const [step, setStep] = useState<Step>(1);
  const [selectedConnector, setSelectedConnector] = useState<ConnectorType | null>(null);
  const [credentials, setCredentials] = useState({ url: '', key: '' });
  const [isConnecting, setIsConnecting] = useState(false);

  // Need to define API Base URL
  const API_BASE_URL = 'http://localhost:8000';

  const handleNextStep1 = async () => {
    if (!selectedConnector) return;

    try {
      const res = await fetch(`${API_BASE_URL}/onboarding/step1`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          step: 1,
          connector_config: {
            connector_name: selectedConnector,
            config: {}
          }
        }),
      });

      if (!res.ok) throw new Error('Failed to select connector');
      setStep(2);
    } catch (err) {
      console.error(err);
      alert('Error selecting connector');
    }
  };

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedConnector) return;

    setIsConnecting(true);

    try {
      // Step 2: Input credentials (and validate)
      const res = await fetch(`${API_BASE_URL}/onboarding/step2`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          step: 2,
          connector_config: {
            connector_name: selectedConnector,
            config: {
              base_url: credentials.url,
              api_key: credentials.key
            }
          }
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || 'Connection failed');
      }

      const data = await res.json();
      console.log('Connected:', data);

      // We can also call step 4 directly here to finalize if we skip step 3 in this simplified UI flow
      // or we just move to success. Let's move to success, assuming step 4 acts in background or next UI iteration.
      // For now, let's just finalize immediately to show full flow.

      const resFinal = await fetch(`${API_BASE_URL}/onboarding/step4`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          step: 4,
          connector_id: data.connector_id
        }),
      });

      if (!resFinal.ok) throw new Error('Finalization failed');

      setStep(3);
    } catch (err) {
      console.error(err);
      alert(err instanceof Error ? err.message : 'Connection failed');
    } finally {
      setIsConnecting(false);
    }
  };

  const resetFlow = () => {
    setStep(1);
    setSelectedConnector(null);
    setCredentials({ url: '', key: '' });
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1>Universal Agentic Fabric</h1>
        <p className="text-secondary text-lg">Plug-and-play AI Defense Ecosystem</p>
      </motion.div>

      <div className="card w-full max-w-2xl relative overflow-hidden">
        <AnimatePresence mode="wait">

          {/* STEP 1: Select Data Source */}
          {step === 1 && (
            <motion.div
              key="step1"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
            >
              <h2>Select Data Source</h2>
              <p className="mb-6 text-sm text-secondary">Choose a security tool to integrate into the fabric.</p>

              <div className="grid-cols-2">
                {connectors.map((c) => (
                  <div
                    key={c.id}
                    className={`connector-card ${selectedConnector === c.id ? 'selected' : ''}`}
                    onClick={() => setSelectedConnector(c.id)}
                  >
                    <div className="mb-3 text-primary">{c.icon}</div>
                    <strong className="text-lg">{c.name}</strong>
                    <span className="text-xs text-secondary mt-1 text-center">{c.description}</span>
                  </div>
                ))}
              </div>

              <div className="mt-8 flex justify-end">
                <button
                  disabled={!selectedConnector}
                  onClick={handleNextStep1}
                  className="flex items-center gap-2"
                >
                  Next Step <ArrowRight size={18} />
                </button>
              </div>
            </motion.div>
          )}

          {/* STEP 2: Configure Credentials */}
          {step === 2 && selectedConnector && (
            <motion.div
              key="step2"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
            >
              <h2>Configure {connectors.find(c => c.id === selectedConnector)?.name}</h2>
              <p className="mb-6 text-sm text-secondary">Enter the necessary credentials for secure access.</p>

              <form onSubmit={handleConnect}>
                <label>API Endpoint / URL</label>
                <input
                  type="text"
                  placeholder="e.g. https://api.example.com"
                  value={credentials.url}
                  onChange={e => setCredentials({ ...credentials, url: e.target.value })}
                  required
                />

                <label>API Key / Access Token</label>
                <input
                  type="password"
                  placeholder="sk_..."
                  value={credentials.key}
                  onChange={e => setCredentials({ ...credentials, key: e.target.value })}
                  required
                />

                <div className="mt-8 flex gap-4">
                  <button type="button" onClick={() => setStep(1)} className="back-btn flex items-center justify-center gap-2">
                    <ArrowLeft size={18} /> Back
                  </button>
                  <button type="submit" disabled={isConnecting} className="flex-1 flex items-center justify-center gap-2">
                    {isConnecting ? 'Connecting...' : 'Connect Interface'}
                    {!isConnecting && <Server size={18} />}
                  </button>
                </div>
              </form>
            </motion.div>
          )}

          {/* STEP 3: Success */}
          {step === 3 && (
            <motion.div
              key="step3"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center py-8"
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 200, damping: 10 }}
                className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-green-900/30 text-green-500 mb-6"
              >
                <CheckCircle size={48} />
              </motion.div>

              <h2>Integration Complete!</h2>
              <p className="text-secondary max-w-sm mx-auto mb-8">
                The content source has been successfully bridged to the Agentic Fabric. Data ingestion will begin shortly.
              </p>

              <button onClick={resetFlow} className="w-full">
                Connect Another Source
              </button>
            </motion.div>
          )}

        </AnimatePresence>
      </div>
    </div>
  );
}

export default App;
