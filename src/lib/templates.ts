export interface EmailTemplate {
  id: string;
  name: string;
  description: string;
  raw: string;
}

export const EMAIL_TEMPLATES: EmailTemplate[] = [
  {
    id: 'paypal-spoof',
    name: 'PayPal Account Suspended',
    description: 'Classic account suspension phishing',
    raw: `From: "PayPal Security" <security@paypa1-secure.com>
To: user@example.com
Subject: Urgent: Your PayPal account has been suspended
Reply-To: support@paypa1-secure.com
Date: Mon, 15 Jul 2024 10:30:00 +0000

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been suspended due to suspicious login attempts.

To restore access, please verify your account immediately by clicking the link below:

http://paypa1-secure.com/verify?account=restore

If you do not verify your account within 24 hours, your account will be permanently deactivated.

Click here to confirm your identity: http://paypa1-secure.com/login

Thank you,
PayPal Security Team`,
  },
  {
    id: 'bank-otp',
    name: 'Bank OTP Scam',
    description: 'Fake bank security alert',
    raw: `From: "Bank of America" <noreply@bankofamerica-secure.net>
To: customer@example.com
Subject: Security Alert: Unusual sign-in activity detected
Reply-To: fraud@bankofamerica-secure.net
Date: Tue, 16 Jul 2024 14:00:00 +0000

Dear Valued Customer,

We noticed unauthorized access to your account. Your account has been restricted for your security.

Please update your payment information immediately to avoid termination:

http://192.168.1.5/bank/verify

Enter your credentials to confirm your identity and restore access.

Bank of America Security`,
  },
  {
    id: 'microsoft365',
    name: 'Microsoft 365 Password Expiry',
    description: 'Enterprise credential phishing',
    raw: `From: "Microsoft 365 Team" <admin@microsoft-support-portal.com>
To: employee@company.com
Subject: Your password has expired - Action required
Reply-To: it@microsoft-support-portal.com
Date: Wed, 17 Jul 2024 09:15:00 +0000

Dear User,

Your Microsoft 365 password has expired. You must reset your password immediately to continue using your account.

Click here to reset your password: http://microsoft-support-portal.com/reset

Failure to act now will result in your account being disabled.

Microsoft 365 Team`,
  },
  {
    id: 'package-delivery',
    name: 'FedEx Package Pending',
    description: 'Delivery notification scam',
    raw: `From: "FedEx" <delivery@fedex-shipment-tracking.xyz>
To: recipient@example.com
Subject: Your package is waiting for delivery - Confirm address
Date: Thu, 18 Jul 2024 11:00:00 +0000

Dear Customer,

Your package with tracking number 7723194 is pending delivery. Please confirm your shipping address:

http://fedex-shipment-tracking.xyz/confirm?track=7723194

A small delivery fee of $1.99 is required to release the package.

FedEx Delivery Services`,
  },
  {
    id: 'crypto-invoice',
    name: 'Bitcoin Invoice Scam',
    description: 'Crypto payment extortion',
    raw: `From: "Security Team" <hacker@anonymous-mail.su>
To: victim@example.com
Subject: Important: Your account has been compromised
Date: Fri, 19 Jul 2024 16:00:00 +0000

Dear Sir/Madam,

I have hacked your device and recorded you through your webcam. I have access to all your accounts.

Send $500 in Bitcoin to the following address within 48 hours, or I will release the footage to all your contacts.

bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

Do not reply to this email. This is your final warning.`,
  },
  {
    id: 'apple-id',
    name: 'Apple ID Locked',
    description: 'Apple credential phishing',
    raw: `From: "Apple" <appleid@apple-secure-verify.com>
To: user@icloud.com
Subject: Your Apple ID has been locked for security reasons
Reply-To: appleid@apple-secure-verify.com
Date: Sat, 20 Jul 2024 08:00:00 +0000

Dear User,

Your Apple ID has been locked due to multiple failed sign-in attempts. We detected unauthorized activity on your account.

Verify your account to unlock it immediately:

https://apple-secure-verify.com/unlock

If you do not verify your identity, your Apple ID will be permanently disabled.

Apple Support`,
  },
  {
    id: 'hr-payroll',
    name: 'HR Payroll Update',
    description: 'Corporate HR phishing',
    raw: `From: "HR Department" <hr@company-payroll-update.com>
To: employee@company.com
Subject: Action Required: Update your direct deposit information
Date: Sun, 21 Jul 2024 12:00:00 +0000

Dear Employee,

Our payroll system has been updated. You must update your direct deposit information to ensure your salary is processed correctly.

Please log in to the HR portal to update your details:

http://company-payroll-update.com/portal

This must be completed before the next pay cycle.

Human Resources`,
  },
  {
    id: 'legit-newsletter',
    name: 'Legitimate Newsletter',
    description: 'Safe email for comparison',
    raw: `From: "Tech News" <newsletter@technews.com>
To: subscriber@example.com
Subject: This week in tech - July 2024
Date: Mon, 22 Jul 2024 09:00:00 +0000

Hi there,

Here are this week's top stories:

- New JavaScript framework released
- Cloud computing trends for 2024
- Best practices for web security

Read the full articles on our website: https://technews.com/weekly

Thanks for reading!
Tech News Team`,
  },
  {
    id: 'google-security',
    name: 'Google Security Alert',
    description: 'Google account phishing',
    raw: `From: "Google Security" <no-reply@google-accounts-verify.com>
To: user@gmail.com
Subject: Security alert: Someone tried to sign in to your account
Reply-To: security@google-accounts-verify.com
Date: Tue, 23 Jul 2024 15:30:00 +0000

Dear User,

Someone tried to sign in to your Google Account from a new device. If this was you, you can ignore this message.

If not, please review your account security immediately:

https://google-accounts-verify.com/review

Your account may be at risk. Confirm your identity to secure it.

Google Security Team`,
  },
  {
    id: 'amazon-order',
    name: 'Amazon Order Confirmation',
    description: 'Amazon order spoof',
    raw: `From: "Amazon" <orders@amazon-confirmation-update.com>
To: buyer@example.com
Subject: Your Amazon order #112-8839471 has been confirmed
Date: Wed, 24 Jul 2024 10:00:00 +0000

Dear Customer,

Thank you for your purchase. Your order has been confirmed.

There is a problem with your payment method. Please update your billing information:

http://amazon-confirmation-update.com/payment?order=112-8839471

Your order will not ship until payment is confirmed.

Amazon Customer Service`,
  },
];

export const PHISHING_URL_SAMPLES = [
  'http://paypa1-secure.com/verify',
  'http://192.168.1.5/bank/login',
  'http://amazon-confirmation-update.com/payment',
  'https://apple-secure-verify.com/unlock',
  'http://google-accounts-verify.com/review',
];
