import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Check, X, Clock } from 'lucide-react';

interface PendingOperation {
    id: string;
    risk_score: number;
    description: string;
    action_type: string;
    target: string;
    created_at: string;
    status: string;
}

const API_BASE_URL = 'http://localhost:8000';

export function Approvals() {
    const [approvals, setApprovals] = useState<PendingOperation[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchApprovals = async () => {
        try {
            const res = await fetch(`${API_BASE_URL}/approvals/`);
            const data = await res.json();
            setApprovals(data);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchApprovals();
        const interval = setInterval(fetchApprovals, 5000);
        return () => clearInterval(interval);
    }, []);

    const handleDecision = async (id: string, decision: 'approve' | 'reject') => {
        try {
            await fetch(`${API_BASE_URL}/approvals/${id}/${decision}`, { method: 'POST' });
            // Optimistic update
            setApprovals(current => current.filter(op => op.id !== id));
        } catch (err) {
            alert(`Failed to ${decision} operation`);
        }
    };

    return (
        <div className="w-full max-w-4xl">
            <div className="flex items-center gap-3 mb-6">
                <AlertTriangle className="text-yellow-500" size={32} />
                <h1>Pending Approvals</h1>
            </div>

            {loading && <p>Loading...</p>}

            <div className="grid gap-4">
                {approvals.length === 0 && !loading && (
                    <div className="card text-center py-12 text-secondary">
                        <Check size={48} className="mx-auto mb-4 text-green-500 opacity-50" />
                        <p>No pending operations. All systems operational.</p>
                    </div>
                )}

                {approvals.map((op) => (
                    <motion.div
                        key={op.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-l-4 border-l-yellow-500"
                    >
                        <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                                <span className="bg-red-900/50 text-red-200 text-xs px-2 py-1 rounded font-bold">
                                    RISK SCORE: {op.risk_score}
                                </span>
                                <span className="text-xs text-secondary flex items-center gap-1">
                                    <Clock size={12} /> {new Date(op.created_at).toLocaleTimeString()}
                                </span>
                            </div>
                            <h3 className="text-lg font-semibold m-0">{op.description}</h3>
                            <p className="text-sm text-secondary m-0 mt-1">
                                Target: <code className="bg-black/30 px-1 rounded">{op.target}</code> • Action: {op.action_type}
                            </p>
                        </div>

                        <div className="flex gap-2 w-full md:w-auto">
                            <button
                                onClick={() => handleDecision(op.id, 'reject')}
                                className="flex-1 md:flex-none bg-red-900/30 hover:bg-red-900/50 text-red-200 border-red-800"
                            >
                                <X size={18} className="mr-1" /> Reject
                            </button>
                            <button
                                onClick={() => handleDecision(op.id, 'approve')}
                                className="flex-1 md:flex-none bg-green-900/30 hover:bg-green-900/50 text-green-200 border-green-800"
                            >
                                <Check size={18} className="mr-1" /> Approve
                            </button>
                        </div>
                    </motion.div>
                ))}
            </div>
        </div>
    );
}
