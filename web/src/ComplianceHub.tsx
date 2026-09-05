import React, { useEffect, useState } from 'react';

interface AVVData {
  tenant_name: string;
  customer_name: string;
  contract_date: string;
  technical_organizational_measures: string[];
  is_cis_compliant: boolean;
  compliance_score: number;
}

interface ComplianceHubProps {
  customerId: number;
  tenantId: string;
}

export const ComplianceHub: React.FC<ComplianceHubProps> = ({ customerId, tenantId }) => {
  const [avv, setAvv] = useState<AVVData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetch(`/api/v1/compliance/avv?customer_id=${customerId}`, {
      headers: { 'X-Tenant-ID': tenantId }
    })
      .then(res => {
        if (!res.ok) throw new Error('Fehler beim Laden der AVV-Daten');
        return res.json();
      })
      .then(data => {
        setAvv(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, [customerId, tenantId]);

  if (loading) return <div className="p-6 text-gray-500">Lade Compliance- & AVV-Daten...</div>;
  if (error) return <div className="p-6 text-red-600">Fehler: {error}</div>;
  if (!avv) return <div className="p-6 text-gray-500">Keine Daten verfügbar.</div>;

  return (
    <div className="p-8 max-w-5xl mx-auto bg-white border border-gray-200 shadow-lg rounded-lg">
      <div className="flex justify-between items-center mb-8 border-b pb-4">
        <h1 className="text-3xl font-serif text-gray-900">Auftragsverarbeitungsvertrag (Art. 28 DSGVO)</h1>
        <button 
          onClick={() => window.print()} 
          className="bg-blue-800 hover:bg-blue-700 text-white px-6 py-2 shadow print:hidden rounded transition"
        >
          PDF Export (NIS2)
        </button>
      </div>

      <div className="space-y-6 text-gray-800">
        <p>Zwischen <strong>{avv.customer_name}</strong> (Auftraggeber) und <strong>{avv.tenant_name}</strong> (Auftragnehmer).</p>
        
        <h3 className="text-xl font-bold mt-6 text-gray-900">1. Technische und organisatorische Maßnahmen (TOMs)</h3>
        <p className="text-gray-600">Der Auftragnehmer sichert die Einhaltung folgender, durch Echtzeit-Telemetrie validierter Maßnahmen zu:</p>
        <ul className="list-disc pl-6 space-y-2">
          {avv.technical_organizational_measures.map((measure, idx) => (
            <li key={idx} className="text-gray-700">{measure}</li>
          ))}
        </ul>

        <div className="mt-8 p-4 bg-gray-50 border-l-4 border-blue-500 shadow-sm rounded-r-lg">
          <h4 className="font-bold text-gray-900">Echtzeit-Compliance Score</h4>
          <p className="text-2xl font-bold text-blue-600">{avv.compliance_score}% CIS Level 1 Abdeckung</p>
          <p className="text-sm text-gray-500 mt-1">
            Status: <span className={avv.is_cis_compliant ? 'text-green-600 font-semibold' : 'text-amber-600 font-semibold'}>
              {avv.is_cis_compliant ? 'Audit-Ready' : 'Maßnahmen erforderlich'}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
};
