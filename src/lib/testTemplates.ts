export interface TestTemplate {
  id: string;
  name: string;
  description: string;
  expectedClassification: 'safe' | 'suspicious' | 'phishing';
  raw: string;
}

const rfcDate = () => new Date().toUTCString();

export const TEST_TEMPLATES: TestTemplate[] = [
  {
    id: 'safe-business',
    name: 'Safe business email',
    description: 'Normal internal business email with no links.',
    expectedClassification: 'safe',
    raw: `From: Alice Nguyen <alice@acme-corp.com>
To: bob@acme-corp.com
Subject: Q3 planning doc
Date: ${rfcDate()}
Message-ID: <safe-business-001@acme-corp.com>

Hi Bob,

Attached is the Q3 planning doc for review before Thursday's meeting.
Let me know if you have any questions.

Thanks,
Alice`,
  },
  {
    id: 'http-login',
    name: 'HTTP login link',
    description: 'Email containing an HTTP link with login/verify keywords.',
    expectedClassification: 'suspicious',
    raw: `From: security@secure-login.example.test
To: user@example.net
Subject: Please verify your account
Date: ${rfcDate()}
Message-ID: <http-login-001@secure-login.example.test>

Your account requires verification. Please visit the link below to confirm.

http://secure-login.example.test/account/verify

Thank you.`,
  },
  {
    id: 'urgent-bank',
    name: 'Urgent bank-verification email',
    description: 'Urgent language + HTTP banking link + credential request.',
    expectedClassification: 'phishing',
    raw: `From: "Bank of America Security" <noreply@bank-secure.example.test>
To: victim@example.net
Subject: URGENT: Your account has been suspended!
Date: ${rfcDate()}
Message-ID: <urgent-bank-001@bank-secure.example.test>
Reply-To: verification@bank-verify.example.test
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Dear Customer,

Your account has been suspended due to suspicious activity. You must verify your identity immediately or your account will be permanently closed within 24 hours.

Click here to confirm your identity now:
http://bank-secure.example.test/verify/login?account=update

Enter your password and OTP to restore access.

Do not ignore this message!`,
  },
  {
    id: 'reply-to-mismatch',
    name: 'Reply-To mismatch',
    description: 'From domain differs from Reply-To domain.',
    expectedClassification: 'phishing',
    raw: `From: "IT Support" <itsupport@internal-mail.example.org>
To: user@example.org
Subject: Re: your request
Date: ${rfcDate()}
Message-ID: <reply-mismatch-001@example.org>
Reply-To: itsupport-external@attacker.example.test

Hello,

Following up on your ticket. Please reply to this email with your credentials so we can proceed.

Thanks,
IT`,
  },
  {
    id: 'display-name-spoof',
    name: 'Display-name spoofing',
    description: 'Display name claims Microsoft but domain is not Microsoft.',
    expectedClassification: 'phishing',
    raw: `From: "Microsoft Security Team" <security@m1crosoft-alerts.example.test>
To: user@example.net
Subject: Unusual sign-in activity
Date: ${rfcDate()}
Message-ID: <spoof-001@m1crosoft-alerts.example.test>

We detected an unusual sign-in to your Microsoft account. Please verify your identity immediately:

http://m1crosoft-alerts.example.test/signin/verify

Microsoft Security`,
  },
  {
    id: 'shortened-url',
    name: 'Shortened URL',
    description: 'Uses a URL shortener to hide the destination.',
    expectedClassification: 'suspicious',
    raw: `From: promo@deals.example.com
To: user@example.net
Subject: You won a prize!
Date: ${rfcDate()}
Message-ID: <shortened-001@deals.example.com>

Congratulations! Click to claim your reward:
http://bit.ly/3xamplePrize

Offer expires today!`,
  },
  {
    id: 'ip-url',
    name: 'IP-address URL',
    description: 'Link points directly to an IP address over HTTP.',
    expectedClassification: 'phishing',
    raw: `From: "Account Security" <security@accounts.example.test>
To: user@example.net
Subject: Confirm your password
Date: ${rfcDate()}
Message-ID: <ip-url-001@accounts.example.test>

Please confirm your password to avoid suspension:
http://192.168.0.15/login/verify?account=secure

Immediate action required.`,
  },
  {
    id: 'fake-microsoft',
    name: 'Fake Microsoft login alert',
    description: 'Impersonates Microsoft with a spoofed domain and login form.',
    expectedClassification: 'phishing',
    raw: `From: "Microsoft account team" <account-security@micros0ft-verify.example.test>
To: user@example.net
Subject: Microsoft account unusual sign-in activity
Date: ${rfcDate()}
Message-ID: <ms-fake-001@micros0ft-verify.example.test>
Reply-To: recovery@external-recovery.example.test
Authentication-Results: spf=none; dkim=none; dmarc=fail

We detected unusual sign-in activity on your Microsoft account.

Review your account now:
http://micros0ft-verify.example.test/account/login

<form action="http://micros0ft-verify.example.test/submit" method="post">
  <input name="password" type="password" />
  <button>Verify</button>
</form>

Microsoft account team`,
  },
  {
    id: 'gift-card',
    name: 'Gift-card fraud',
    description: 'Gift-card purchase scam with urgent request.',
    expectedClassification: 'phishing',
    raw: `From: "CEO Office" <ceo@executive.example.test>
To: employee@example.net
Subject: URGENT - Need gift cards
Date: ${rfcDate()}
Message-ID: <giftcard-001@executive.example.test>

I need you to purchase $500 in gift cards immediately for a client. This is urgent and confidential.

Reply with confirmation and I will provide instructions.

CEO`,
  },
  {
    id: 'safe-newsletter',
    name: 'Safe newsletter',
    description: 'Normal HTTPS newsletter with matching links.',
    expectedClassification: 'safe',
    raw: `From: "Tech Weekly" <newsletter@techweekly.com>
To: subscriber@example.com
Subject: This week in tech
Date: ${rfcDate()}
Message-ID: <newsletter-001@techweekly.com>

Here are this week's top stories:

<a href="https://techweekly.com/story/123">Read: AI advances</a>
<a href="https://techweekly.com/unsubscribe">Unsubscribe</a>

Thanks for reading!`,
  },
];
