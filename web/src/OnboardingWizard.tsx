import React, { useState } from 'react';

export const OnboardingWizard: React.FC = () => {
  const [os, setOs] = useState<'linux' | 'windows'>('linux');
  const [payload, setPayload] = useState<{ token: string; bash_script: string; ps1_script: string } | null>(null);

  const generatePayload = async () => {
    const res = await fetch('/api/v1/onboarding/generate', {
      method: 'POST',
      headers: { 'X-Tenant-ID': 'systemhaus-xy' }
    });
    const data = await res.json();
    setPayload(data);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto bg-white rounded-xl shadow-md space-y-6">
      <h2 className="text-2xl font-bold text-gray-900">Neuen Server anbinden (JIT-Enrollment)</h2>
      <p className="text-gray-600">Generieren Sie einen kurzlebigen Befehl zur automatisierten Agenten-Installation und SSH-Tunnel-Etablierung.</p>
      
      <div className="flex space-x-4">
        <button onClick={() => setOs('linux')} className={`px-4 py-2 rounded ${os === 'linux' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>Linux (Bash)</button>
        <button onClick={() => setOs('windows')} className={`px-4 py-2 rounded ${os === 'windows' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>Windows (PS)</button>
      </div>

      <button onClick={generatePayload} className="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded">
        Sicheren Onboarding-Befehl generieren
      </button>

      {payload && (
        <div className="bg-gray-900 text-green-400 p-4 rounded-md overflow-x-auto font-mono text-sm">
          <code>{os === 'linux' ? payload.bash_script : payload.ps1_script}</code>
        </div>
      )}
    </div>
  );
};
