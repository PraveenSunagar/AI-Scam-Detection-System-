"""
Utility functions, dataset generator, and evaluation metrics helpers.
"""

import os
import json
import random
import pandas as pd
from typing import Dict, List, Any


SCAM_SAMPLES_BY_CATEGORY = {
    "Banking / KYC Fraud": [
        "Dear customer, your SBI bank account has been blocked due to incomplete KYC. Update KYC immediately at http://sbi-kyc-verify.xyz/login to avoid permanent deactivation.",
        "URGENT ALERT: Your Wells Fargo account has unauthorized transactions. Verify your identity now: https://wellsfargo-secure-login.top or call +1-800-555-0199.",
        "HDFC Bank Alert: Your netbanking will be suspended in 24 hours. Please update your PAN card details here: http://hdfc-security-update.online",
        "Chase Bank: Suspicious charge of $1,420.90 detected at Apple Store. If not you, reply NO or visit https://chase-fraud-prevention.top to dispute.",
        "Dear User, your Bank of America debit card is temporarily locked. Click http://boa-unlock-card.info to enter your PIN and CVV to restore access.",
        "Alert: Your account has been credited with $5,000.00. To release the pending funds, submit your verification fee of $50 at http://quick-payout.biz",
        "Axis Bank Notice: Your savings account is restricted due to non-compliance. Complete biometric verification at http://axis-kyc-desk.site",
        "ICICI Bank: We noticed unusual login attempts from Russia. Click here to confirm your credentials: http://icici-protect.xyz"
    ],
    "Phishing & Account Security": [
        "Google Security Team: Someone just logged into your Gmail from Moscow, Russia. If this wasn't you, secure your account at https://accounts-google-verify.com/login",
        "Apple ID Alert: Your iCloud account is scheduled for deletion due to suspected fraud. Tap https://appleid-security-recovery.link to cancel deletion.",
        "Netflix Support: We were unable to process your monthly subscription payment. Update your credit card info now: http://netflix-billing-update.top or service will stop.",
        "PayPal Notice: Your account has been limited due to policy violation. Resolve the issue immediately: https://paypal-account-resolve.org",
        "Amazon Support: Your order #902-1823901 for MacBook Pro ($2,199.00) is confirmed. If you didn't place this order, call +1-888-293-1102 to cancel immediately.",
        "Microsoft 365: Your password will expire today. Keep current password by logging in: http://outlook-reauth-portal.com",
        "Meta / Instagram: Copyright infringement detected on your profile. Submit appeal within 24 hours at https://meta-appeal-center.net or account will be banned.",
        "WhatsApp Security: Your registration code is requested on another device. Confirm your identity here: http://whatsapp-verify-now.site"
    ],
    "Lottery & Prize Scam": [
        "CONGRATULATIONS! Your mobile number won $1,500,000 in the 2026 International Mega Millions Lottery. To claim your prize, send your full name and bank info to claim@megawin-lottery.org",
        "You have been selected as the 1st prize winner of a brand new BMW X5 or $50,000 cash! Claim your voucher at http://lucky-draw-winner.biz/claim",
        "Exclusive offer! You won a $1,000 Walmart Gift Card! Click http://bit.ly/walmart-free-gift-card to fill out a short survey and claim today.",
        "Dear Winner, your email won £750,000 in British National Sweepstakes. Reply with your passport copy and fee of £150 to process transfer.",
        "Special reward! You have 5,420 unredeemed reward points worth $542 expiring today. Redeem for cash now at http://points-redeem-cash.top"
    ],
    "Crypto & Investment Fraud": [
        "Elon Musk Giveaway: Send 0.1 BTC to receive 0.5 BTC back immediately! Guaranteed 500% profit. Join official event at http://elon-crypto-event.xyz",
        "Guaranteed 25% daily ROI with automated AI crypto trading bot. Deposit $200 in USDT and withdraw $1,500 by tomorrow: http://crypto-yield-ai.io",
        "Binance Alert: Your withdrawal of 2.45 BTC is pending. Click http://binance-release-wallet.com to approve or reject the transaction.",
        "Exclusive opportunity to buy Pre-Sale Token with guaranteed 100x return. Limited tokens remaining: https://crypto-pump-presale.network",
        "Join our VIP Telegram trading group! Make $5,000 daily with zero risk. Register now: http://vip-signals-trading.co"
    ],
    "Delivery & Package Scam": [
        "USPS Alert: Your parcel could not be delivered on 08/19 due to missing street address. Please update your address and pay $1.99 redelivery fee at http://usps-redelivery-portal.info",
        "FedEx Notification: Tracking #FX-8893921 has a pending customs duty fee of $3.50. Pay online to release package: http://fedex-customs-clearance.top",
        "DHL Express: We attempted delivery of your package twice. Schedule a new delivery time: http://dhl-parcel-reschedule.site or package will be returned to sender.",
        "UPS Tracking: Address confirmation required for parcel 1Z9999999999999999. Verify within 12 hours: http://ups-track-package.online",
        "Royal Mail: Your package is held at regional sorting center due to unpaid tax. Settle payment here: http://royalmail-fee-pay.xyz"
    ],
    "Job & Task Scam": [
        "Hi! Amazon HR is hiring remote part-time workers! Earn $300 - $800 daily by simply rating products. No experience needed. Contact WhatsApp: +1-917-555-0144",
        "Work from home job opportunity: Earn $50/hour liking YouTube videos and following TikTok accounts. Daily instant payout via PayPal/USDT. Tap http://t.me/easy_job_tasks",
        "Congratulations! Your resume was shortlisted for Data Entry Specialist ($45/hr). Buy your starter training software package for $99 at http://remote-career-portal.com to begin.",
        "Urgent requirement: Freelance reviewers needed. Earn $2,000 weekly. Contact HR Manager on Telegram @GlobalHRRecruiter"
    ],
    "Threat & Impersonation Scam": [
        "URGENT: This is Officer Miller from the Federal Tax Police. An arrest warrant has been issued in your name for tax fraud. Call +1-800-555-0188 immediately to avoid arrest.",
        "IRS Final Warning: Legal lawsuit filed against you. You owe $3,450 in back taxes. Pay immediately via Apple Gift Card or local sheriff will arrive at your residence.",
        "Customs & Border Protection: A suspicious parcel containing illegal contraband under your name was seized. Call federal agent at +1-888-555-0133 to resolve case.",
        "Cyber Threat Alert: I have installed spyware on your device and recorded you via webcam. Pay $1,000 in Bitcoin to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 48 hours or video goes to all contacts."
    ]
}

LEGITIMATE_HAM_SAMPLES = [
    "Hey! Are we still meeting for lunch at 12:30 PM at the Italian bistro near downtown?",
    "Your Uber driver is arriving in 3 minutes in a Silver Toyota Camry (License Plate: 7XYZ89).",
    "Your one-time security passcode is 492019 for your Google verification. Do not share this code with anyone.",
    "Hi Mom, I just finished my class and heading to the library. Will be home by 6 PM.",
    "Your Amazon package with order #112-9847192 has been delivered to your front porch. View delivery photo in the app.",
    "Meeting reminder: Team Sprint Planning tomorrow at 10:00 AM on Google Meet. Agenda attached in calendar invite.",
    "Hi David, attached is the revised Q3 financial report for your review. Let me know if you need any adjustments.",
    "Your appointment with Dr. Sarah Jenkins is confirmed for Thursday, Aug 21 at 3:15 PM. Reply C to confirm or R to reschedule.",
    "Your Chase credit card bill of $214.50 is due on Sept 5. Automatic payment is scheduled from your checking account.",
    "Hi team, just pushed the latest bug fix to the main branch. Please pull and run tests locally.",
    "Hey, do you want to grab coffee this afternoon? I'll be in the building until 4 PM.",
    "Your Netflix verification code is 839120. Valid for 10 minutes. If you did not request this, ignore this email.",
    "Thanks for ordering with DoorDash! Your driver John is on the way with your order from Chipotle.",
    "Happy Birthday Alex! Wishing you a fantastic year ahead filled with joy and success!",
    "Flight confirmation: Delta Flight DL428 from JFK to LAX departs at 8:45 AM on Friday. Gate B22.",
    "Reminder: Your library books 'Introduction to Algorithms' and 'Designing Data-Intensive Apps' are due on Friday.",
    "Hey, did you get a chance to review the slides I sent yesterday? We have the client presentation tomorrow morning.",
    "Your electricity bill for the period July 1 to July 31 has been generated. Amount: $84.20. Autopay enabled.",
    "Great work on the demo today everyone! The client was really impressed with our progress.",
    "Can you please pick up some milk and eggs on your way back from the office?"
]


def generate_augmented_dataset(target_size: int = 1200) -> pd.DataFrame:
    """
    Generate an augmented, balanced, multi-vertical dataset
    for training the AI scam classification model.
    """
    rows = []

    # 1. Base Scam Samples
    for category, samples in SCAM_SAMPLES_BY_CATEGORY.items():
        for sample in samples:
            rows.append({
                "text": sample,
                "label": 1,
                "category": category,
                "source": "curated_scam"
            })

    # 2. Base Ham Samples
    for sample in LEGITIMATE_HAM_SAMPLES:
        rows.append({
            "text": sample,
            "label": 0,
            "category": "Legitimate Message",
            "source": "curated_ham"
        })

    # 3. Augmentation templates for Scams
    scam_templates = [
        ("Banking / KYC Fraud", [
            "Your {bank} account #{num} is restricted. Update KYC at {url} within 24h.",
            "Security Notice: {bank} detected suspicious activity. Confirm your login at {url}",
            "Urgent: {bank} card blocked. Call {phone} or visit {url} with your CVV to unblock.",
            "Dear customer, your PAN card is not linked to {bank}. Update immediately: {url}",
            "{bank}: Unauthorized transfer of ${amount} to unknown account. Cancel now: {url}"
        ]),
        ("Phishing & Account Security", [
            "{brand} Alert: Login attempt from {city}. Secure your account now at {url}",
            "Your {brand} subscription has expired. Update billing details at {url} to keep access.",
            "{brand} Security: Password reset requested. If this wasn't you, verify at {url}",
            "Urgent notice from {brand} support: Account will be closed in 12 hours. Tap {url}"
        ]),
        ("Lottery & Prize Scam", [
            "Congratulations! You won ${amount} in {promo}. Claim your prize at {url}",
            "Lucky Winner! Your phone won a free {prize}. Reply YES to claim or visit {url}",
            "You have unclaimed rewards of ${amount}. Withdraw to your account at {url}"
        ]),
        ("Crypto & Investment Fraud", [
            "Double your {crypto} deposit in 24 hours. Send 0.5 {crypto} to receive 1.0 {crypto} at {url}",
            "Guaranteed daily profit of ${amount} with AI crypto trader. Sign up free: {url}",
            "{crypto_exchange}: Pending withdrawal of {amount} {crypto}. Confirm or cancel at {url}"
        ]),
        ("Delivery & Package Scam", [
            "{carrier}: Your package delivery failed. Confirm address & pay ${amount} fee at {url}",
            "Tracking Alert: Package #{num} is on hold at customs. Clear payment: {url}",
            "{carrier} Notice: Delivery rescheduled. View package status here: {url}"
        ]),
        ("Job & Task Scam", [
            "Hiring now: Part time remote assistant. Earn ${amount}/day working from home. WhatsApp: {phone}",
            "Simple online job: Watch videos and earn ${amount} daily. Register here: {url}"
        ]),
        ("Threat & Impersonation Scam", [
            "IRS Warning: Legal warrant #{num} issued for your arrest. Call {phone} immediately to settle.",
            "Police Dept: Case filed against you for unpaid penalty of ${amount}. Contact {phone}."
        ])
    ]

    banks = ["Chase", "Bank of America", "Wells Fargo", "HDFC", "SBI", "Citibank", "Barclays", "ICICI", "Capital One"]
    brands = ["Amazon", "Netflix", "PayPal", "Apple", "Google", "Microsoft", "Facebook", "Instagram", "Dropbox"]
    carriers = ["USPS", "FedEx", "DHL", "UPS", "Royal Mail", "Canada Post"]
    cryptos = ["Bitcoin", "ETH", "USDT", "Solana", "BTC"]
    crypto_exchanges = ["Binance", "Coinbase", "Kraken", "KuCoin"]
    prizes = ["iPhone 16 Pro", "Tesla Model 3", "$1,000 Walmart Gift Card", "PlayStation 5", "Rolex Watch"]
    promos = ["Mega Cash Giveaway", "Annual Customer Reward", "Global Lottery", "Tech Promo Draw"]
    cities = ["Moscow", "Beijing", "Lagos", "São Paulo", "London", "Bucharest"]
    urls = [
        "http://secure-verify-account.xyz/login",
        "http://auth-kyc-desk.online/update",
        "http://bit.ly/claim-reward-now",
        "http://tracking-reschedule-post.top",
        "http://support-unlock-portal.net",
        "http://tinyurl.com/fast-payout-2026",
        "https://billing-resolution-portal.site"
    ]
    phones = ["+1-800-555-0144", "+1-888-555-0199", "+44-20-7946-0912", "+91-9876543210", "+1-917-555-0182"]

    # Generate synthetic scam rows
    for _ in range(600):
        cat, templates = random.choice(scam_templates)
        tmpl = random.choice(templates)
        text = tmpl.format(
            bank=random.choice(banks),
            brand=random.choice(brands),
            carrier=random.choice(carriers),
            crypto=random.choice(cryptos),
            crypto_exchange=random.choice(crypto_exchanges),
            prize=random.choice(prizes),
            promo=random.choice(promos),
            city=random.choice(cities),
            url=random.choice(urls),
            phone=random.choice(phones),
            amount=random.choice(["250", "500", "1,200", "2,500", "10,000", "50,000", "1.5"]),
            num=str(random.randint(100000, 999999))
        )
        rows.append({
            "text": text,
            "label": 1,
            "category": cat,
            "source": "synthetic_scam"
        })

    # 4. Augmentation templates for Legitimate Ham
    ham_templates = [
        "Hey {name}, are we still on for {event} at {time}?",
        "Hi {name}, I left the {item} on your desk. Let me know if you need anything else.",
        "Your verification code for {service} is {otp}. Valid for 5 minutes. Do not share with anyone.",
        "Your order from {store} has shipped! Estimated delivery: {day}. Track in app.",
        "Thanks for dining with {restaurant}! Your receipt for ${amount} has been emailed.",
        "Reminder: Doctor appointment with Dr. {doctor} on {day} at {time}.",
        "Hi team, meeting notes from today's {project} sync are uploaded to Drive.",
        "Can you send me the latest draft for the {project} presentation before 3 PM?",
        "Your monthly electric bill of ${amount} has been paid via automatic debit.",
        "Hey, running about 10 minutes late due to traffic! See you shortly."
    ]

    names = ["Alex", "Sarah", "Michael", "Emma", "David", "Jessica", "James", "Emily", "Daniel"]
    events = ["lunch", "dinner", "coffee", "the movie", "our study session", "gym workout"]
    times = ["12:30 PM", "2:00 PM", "6:15 PM", "7:30 PM", "10:00 AM"]
    items = ["project report", "office keys", "laptop charger", "meeting notes", "book"]
    services = ["Google", "GitHub", "Slack", "Netflix", "LinkedIn", "Discord", "Apple ID"]
    stores = ["Amazon", "Target", "Best Buy", "Nike", "Apple Store", "Sephora"]
    restaurants = ["Chipotle", "Starbucks", "Panera Bread", "Subway", "Sweetgreen"]
    doctors = ["Smith", "Patel", "Johnson", "Williams", "Brown", "Garcia"]
    projects = ["Q3 Marketing Plan", "Backend Refactoring", "Mobile App Redesign", "Security Audit"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "tomorrow"]

    for _ in range(600):
        tmpl = random.choice(ham_templates)
        text = tmpl.format(
            name=random.choice(names),
            event=random.choice(events),
            time=random.choice(times),
            item=random.choice(items),
            service=random.choice(services),
            store=random.choice(stores),
            restaurant=random.choice(restaurants),
            doctor=random.choice(doctors),
            project=random.choice(projects),
            day=random.choice(days),
            otp=str(random.randint(100000, 999999)),
            amount=str(random.randint(12, 180)) + ".50"
        )
        rows.append({
            "text": text,
            "label": 0,
            "category": "Legitimate Message",
            "source": "synthetic_ham"
        })

    df = pd.DataFrame(rows)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def ensure_dataset_exists(csv_path: str = "data/scam_dataset.csv") -> pd.DataFrame:
    """Check if dataset exists; if not, create it and save to disk."""
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        return df
    
    df = generate_augmented_dataset()
    df.to_csv(csv_path, index=False)
    return df
