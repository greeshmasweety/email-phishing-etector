import { VendorResult } from '../lib/virustotal';

export default function VirusTotalTable({ vendors, maliciousCount, totalEngines }: {
  vendors: VendorResult[];
  maliciousCount: number;
  totalEngines: number;
}) {
  if (totalEngines === 0) {
    return (
      <div className="card p-6 text-center text-gray-500">
        No VirusTotal analysis available for this URL.
      </div>
    );
  }

  const maliciousVendors = vendors.filter((v) => v.is_malicious);
  const cleanVendors = vendors.filter((v) => !v.is_malicious);

  return (
    <div className="card overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-200 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center">
            <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div>
            <h3 className="font-semibold text-gray-900">VirusTotal Detection</h3>
            <p className="text-sm text-gray-500">{totalEngines} security vendors analyzed this URL</p>
          </div>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-bold ${maliciousCount > 0 ? 'text-red-600' : 'text-green-600'}`}>
            {maliciousCount}
          </div>
          <div className="text-xs text-gray-500">malicious</div>
        </div>
      </div>

      {maliciousCount > 0 && (
        <div className="px-5 py-3 bg-red-50 border-b border-red-100">
          <p className="text-sm text-red-800 font-medium">
            {maliciousCount} of {totalEngines} security vendors flagged this URL as malicious
          </p>
        </div>
      )}

      <div className="max-h-96 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 sticky top-0">
            <tr>
              <th className="px-5 py-2.5 text-left font-medium text-gray-600">Security Vendor</th>
              <th className="px-5 py-2.5 text-left font-medium text-gray-600">Category</th>
              <th className="px-5 py-2.5 text-left font-medium text-gray-600">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {maliciousVendors.map((v) => (
              <tr key={v.engine_name} className="bg-red-50/50 hover:bg-red-50">
                <td className="px-5 py-2.5 font-medium text-gray-900">{v.engine_name}</td>
                <td className="px-5 py-2.5"><span className="badge bg-red-100 text-red-800">{v.category}</span></td>
                <td className="px-5 py-2.5 text-gray-700">{v.result || '—'}</td>
              </tr>
            ))}
            {cleanVendors.slice(0, 20).map((v) => (
              <tr key={v.engine_name} className="hover:bg-gray-50">
                <td className="px-5 py-2.5 text-gray-700">{v.engine_name}</td>
                <td className="px-5 py-2.5"><span className="badge bg-green-100 text-green-800">{v.category}</span></td>
                <td className="px-5 py-2.5 text-gray-500">{v.result || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {cleanVendors.length > 20 && (
        <div className="px-5 py-2.5 text-center text-xs text-gray-400 border-t border-gray-100">
          Showing {maliciousVendors.length} malicious + 20 of {cleanVendors.length} clean vendors
        </div>
      )}
    </div>
  );
}
