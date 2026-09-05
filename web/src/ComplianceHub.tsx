import React, { useEffect, useState } from 'react';

interface AVVData {
  tenant_name: string;
  customer_name: string;
  contract_date: string;
  technical_organizational_measures: string[];
  is_cis_compliant: boolean;
  compliance_score: number;
}

export const ComplianceHub: React.FC = () => {
  const [avv, setAvv] = useState<AVVData | null>(null);

  useEffect(() => {
    fetch('/api/v1/compliance/avv?customer_id=1', {
      headers: { 'X-Tenant-ID': 'systemhaus-xy' }
    })
      .then(res => res.json())
      .then(setAvv);
  }, []);

  if (!avv) return <div className="p-6">Lade Compliance-Daten...</div>;

  return (
    <div className="p-8 max-w-5xl mx-auto bg-gray-50 border border-gray-200 shadow-lg">
      <div className="flex justify-between items-center mb-8 border-b pb-4">
        <h1 className="text-3xl font-serif text-gray-900">Auftragsverarbeitungsvertrag (Art. 28 DSGVO)</h1>
        <button className="bg-blue-800 text-white px-6 py-2 shadow print:hidden">PDF Export (NIS2)</button>
      </div>

      <div className="space-y-6 text-gray-800">
        <p>Zwischen <strong>{avv.customer_name}</strong> (Auftraggeber) und <strong>{avv.tenant_name}</strong> (Auftragnehmer).</p>
        
        <h3 className="text-xl font-bold mt-6">1. Technische und organisatorische Maßnahmen (TOMs)</h3>
        <p>Der Auftragnehmer sichert die Einhaltung folgender, durch Echtzeit-Telemetrie validierter Maßnahmen zu:</p>
        <ul className="list-disc pl-6 space-y-2">
          {avv.technical_organizational_measures.map((measure, idx) => (
            <li key={idx}>{measure}</li>
          ))}
        </ul>

        <div className="mt-8 p-4 bg-white border-l-4 border-blue-500 shadow-sm">
          <h4 className="font-bold text-gray-900">Echtzeit-Compliance Score</h4>
          <p className="text-2xl font-bold text-blue-600">{avv.compliance_score}% CIS Level 1 Abdeckung</p>
          <p className="text-sm text-gray-500">Status: {avv.is_cis_compliant ? 'Audit-Ready' : 'Maßnahmen erforderlich'}</p>
        </div>
      </div>
    </div>
  );
};
