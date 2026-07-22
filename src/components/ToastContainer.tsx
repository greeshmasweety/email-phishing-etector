import { useAlerts } from '../context/AlertContext';
import { Link } from 'react-router-dom';

export default function ToastContainer() {
  const { toasts, dismissToast } = useAlerts();

  return (
    <div className="fixed top-4 right-4 z-50 space-y-3 max-w-sm">
      {toasts.map((toast) => {
        const isMalicious = toast.type === 'malicious';
        const isPhishing = toast.type === 'phishing';
        return (
          <div
            key={toast.id}
            className={`animate-slide-in rounded-xl shadow-lg overflow-hidden border-l-4 ${
              isMalicious ? 'bg-red-900 border-red-500' : isPhishing ? 'bg-red-50 border-red-500' : 'bg-blue-50 border-blue-500'
            }`}
          >
            <div className="p-4">
              <div className="flex items-start gap-3">
                <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${
                  isMalicious ? 'bg-red-800' : isPhishing ? 'bg-red-100' : 'bg-blue-100'
                }`}>
                  <svg className={`w-6 h-6 ${isMalicious ? 'text-red-200' : isPhishing ? 'text-red-600' : 'text-blue-600'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className={`font-semibold text-sm ${isMalicious ? 'text-red-100' : isPhishing ? 'text-red-900' : 'text-blue-900'}`}>
                    {toast.title}
                  </h4>
                  <p className={`text-sm mt-1 ${isMalicious ? 'text-red-200' : isPhishing ? 'text-red-700' : 'text-blue-700'}`}>
                    {toast.message}
                  </p>
                  {toast.sender && (
                    <p className={`text-xs mt-1 ${isMalicious ? 'text-red-300' : 'text-gray-500'}`}>
                      From: {toast.sender}
                    </p>
                  )}
                  <div className="flex items-center gap-3 mt-2">
                    {toast.email_id && (
                      <Link to={`/emails/${toast.email_id}`} onClick={() => dismissToast(toast.id)}
                        className={`text-xs font-medium ${isMalicious ? 'text-red-200 hover:text-white' : 'text-blue-600 hover:text-blue-800'} underline`}>
                        View Details
                      </Link>
                    )}
                    <button onClick={() => dismissToast(toast.id)}
                      className={`text-xs ${isMalicious ? 'text-red-300 hover:text-white' : 'text-gray-500 hover:text-gray-700'}`}>
                      Dismiss
                    </button>
                  </div>
                </div>
                <button onClick={() => dismissToast(toast.id)}
                  className={`flex-shrink-0 ${isMalicious ? 'text-red-300 hover:text-white' : 'text-gray-400 hover:text-gray-600'}`}>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            <div className={`h-1 ${isMalicious ? 'bg-red-600' : 'bg-red-400'}`}>
              <div className="h-full bg-white/30 animate-pulse" style={{ width: '100%' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
