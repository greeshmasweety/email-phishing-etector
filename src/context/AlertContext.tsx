import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { supabase } from '../lib/supabase';

export interface AlertNotification {
  id: string;
  type: 'phishing' | 'malicious' | 'info' | 'success';
  title: string;
  message: string;
  email_id?: string;
  sender?: string;
  subject?: string;
  risk_score?: number;
  timestamp: number;
  read: boolean;
}

interface AlertContextValue {
  alerts: AlertNotification[];
  unreadCount: number;
  showAlert: (alert: Omit<AlertNotification, 'id' | 'timestamp' | 'read'>) => void;
  dismissAlert: (id: string) => void;
  markAllRead: () => void;
  clearAlerts: () => void;
  toasts: AlertNotification[];
  dismissToast: (id: string) => void;
}

const AlertContext = createContext<AlertContextValue | null>(null);

export function AlertProvider({ children }: { children: ReactNode }) {
  const [alerts, setAlerts] = useState<AlertNotification[]>([]);
  const [toasts, setToasts] = useState<AlertNotification[]>([]);
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);

  const showAlert = useCallback((alert: Omit<AlertNotification, 'id' | 'timestamp' | 'read'>) => {
    const id = `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const notification: AlertNotification = {
      ...alert,
      id,
      timestamp: Date.now(),
      read: false,
    };
    setAlerts((prev) => [notification, ...prev].slice(0, 100));

    if (alert.type === 'phishing' || alert.type === 'malicious') {
      setToasts((prev) => [notification, ...prev].slice(0, 3));
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 8000);
    }
  }, []);

  const dismissAlert = useCallback((id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const markAllRead = useCallback(() => {
    setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
  }, []);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
    setToasts([]);
  }, []);

  useEffect(() => {
    supabase
      .from('emails')
      .select('scan_timestamp')
      .order('scan_timestamp', { ascending: false })
      .limit(1)
      .maybeSingle()
      .then(({ data }) => {
        if (data?.scan_timestamp) setLastScanTime(data.scan_timestamp);
      });
  }, []);

  useEffect(() => {
    const channel = supabase
      .channel('email-alerts')
      .on('postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'emails' },
        (payload) => {
          const email = payload.new as any;
          if (email.classification && email.classification !== 'safe') {
            const isMalicious = email.classification === 'malicious';
            showAlert({
              type: isMalicious ? 'malicious' : 'phishing',
              title: isMalicious ? 'Malicious Email Detected!' : 'Phishing Email Detected!',
              message: `Risk score: ${email.risk_score}/100 — "${email.subject}"`,
              email_id: email.id,
              sender: email.sender_email,
              subject: email.subject,
              risk_score: email.risk_score,
            });
          }
        }
      )
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [showAlert]);

  useEffect(() => {
    const interval = setInterval(async () => {
      const { data } = await supabase
        .from('emails')
        .select('id, sender_email, subject, risk_score, classification, scan_timestamp')
        .gt('scan_timestamp', lastScanTime || '1970-01-01')
        .order('scan_timestamp', { ascending: false })
        .limit(10);

      if (data && data.length > 0) {
        const latest = data[0];
        setLastScanTime(latest.scan_timestamp);
        for (const email of data) {
          if (email.classification !== 'safe') {
            const isMalicious = email.classification === 'malicious';
            showAlert({
              type: isMalicious ? 'malicious' : 'phishing',
              title: isMalicious ? 'Malicious Email Detected!' : 'Phishing Email Detected!',
              message: `Risk score: ${email.risk_score}/100 — "${email.subject}"`,
              email_id: email.id,
              sender: email.sender_email,
              subject: email.subject,
              risk_score: email.risk_score,
            });
          }
        }
      }
    }, 15000);

    return () => clearInterval(interval);
  }, [lastScanTime, showAlert]);

  const unreadCount = alerts.filter((a) => !a.read).length;

  return (
    <AlertContext.Provider value={{ alerts, unreadCount, showAlert, dismissAlert, markAllRead, clearAlerts, toasts, dismissToast }}>
      {children}
    </AlertContext.Provider>
  );
}

export function useAlerts() {
  const ctx = useContext(AlertContext);
  if (!ctx) throw new Error('useAlerts must be used within AlertProvider');
  return ctx;
}
