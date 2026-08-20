"""
Text Preprocessing and Feature Extraction for AI Scam Detection System.
Handles text normalization, entity extraction (URLs, phones, currency),
and scam indicator heuristic scoring.
"""

import re
import html
from typing import Dict, List, Any, Tuple


# Common English stopwords (compact set to avoid external NLTK download issues)
STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such", "than",
    "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there",
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this",
    "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't",
    "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's",
    "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom",
    "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll",
    "you're", "you've", "your", "yours", "yourself", "yourselves"
}

# Specific scam triggers and weighted categories
TRIGGER_PATTERNS = {
    "urgency": [
        r"\b(urgent|immediately|act now|hurry|instant|limited time|last chance|within \d+ (hours?|mins?|minutes?|days?))\b",
        r"\b(account (suspended|blocked|locked|compromised|terminated|restricted|disabled))\b",
        r"\b(final notice|immediate action|deadline|expire[sd]? (today|soon|in \d+))\b",
        r"\b(unauthorized (access|transaction|login|activity))\b",
        r"\b(verify your identity|confirm immediately|security alert)\b"
    ],
    "financial": [
        r"\b(free money|claim your (prize|reward|grant|refund)|lottery|jackpot|won \$?\d+)\b",
        r"\b(wire transfer|western union|moneygram|crypto|bitcoin|eth|usdt|binance)\b",
        r"\b(gift cards?|itunes card|steam card|google play card|prepaid card)\b",
        r"\b(otp|one time password|cvv|pin code|security code|bank login|routing number)\b",
        r"\b(kyc (update|verification|pending|required)|pan card|ssn|social security)\b",
        r"\b(double your (money|investment|crypto)|guaranteed return|risk free)\b",
        r"\b(tax refund|irs refund|stimulus check|unclaimed inheritance)\b",
        r"\b(cashback|congratulations you have won|credited to your account)\b"
    ],
    "threat": [
        r"\b(arrest warrant|lawsuit|legal action|court summons|police department|fbi|irs agent)\b",
        r"\b(jail time|criminal charges|federal penalty|unpaid taxes|fine of \$?\d+)\b",
        r"\b(blackmail|recorded video|compromised camera|pay or we release)\b"
    ],
    "phishing_action": [
        r"\b(click (here|below|link|on the link)|tap (here|to claim|to verify))\b",
        r"\b(visit (http|https|www|bit\.ly|tinyurl|t\.co))\b",
        r"\b(download attachment|open invoice|update billing|login to verify)\b",
        r"\b(fill (out )?(the )?form|reply with (otp|password|code|details))\b",
        r"\b(track your package|delivery failed|customs fee of \$?\d+)\b"
    ]
}


class TextPreprocessor:
    """Preprocessor class providing text cleaning, feature extraction, and trigger analysis."""

    def __init__(self):
        self.url_regex = re.compile(
            r"(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/[^\s]+|bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+|t\.co\/[^\s]+)",
            re.IGNORECASE
        )
        self.phone_regex = re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{10}\b",
            re.IGNORECASE
        )
        self.email_regex = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        )
        self.currency_regex = re.compile(
            r"(\$|€|£|₹|USD|EUR|GBP|INR|BTC|ETH)\s?(\d+([,\.]\d+)*)",
            re.IGNORECASE
        )
        self.otp_code_regex = re.compile(
            r"\b(?:code|otp|pin|passcode)\s*(?:is|:)?\s*([0-9]{4,8})\b",
            re.IGNORECASE
        )

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract structured entities such as URLs, phone numbers, emails, and currencies."""
        if not text:
            return {"urls": [], "phones": [], "emails": [], "currencies": []}

        urls = [m.group(0) for m in self.url_regex.finditer(text)]
        phones = [m.group(0).strip() for m in self.phone_regex.finditer(text)]
        emails = [m.group(0) for m in self.email_regex.finditer(text)]
        currencies = [m.group(0) for m in self.currency_regex.finditer(text)]

        return {
            "urls": list(set(urls)),
            "phones": list(set(phones)),
            "emails": list(set(emails)),
            "currencies": list(set(currencies))
        }

    def clean_text(self, text: str, remove_stopwords: bool = False) -> str:
        """
        Normalize text:
        - Unescape HTML entities
        - Replace URLs and phones with tokens
        - Normalize whitespaces and lowercase
        - Optionally filter stopwords
        """
        if not text or not isinstance(text, str):
            return ""

        # Unescape HTML
        cleaned = html.unescape(text)

        # Replace URLs, emails, and phones with standard semantic tokens
        cleaned = self.url_regex.sub(" [URL] ", cleaned)
        cleaned = self.email_regex.sub(" [EMAIL] ", cleaned)
        cleaned = self.phone_regex.sub(" [PHONE] ", cleaned)
        cleaned = self.currency_regex.sub(" [CURRENCY] ", cleaned)

        # Lowercase
        cleaned = cleaned.lower()

        # Remove special characters keeping basic punctuation structure
        cleaned = re.sub(r"[^a-z0-9\s\[\]]", " ", cleaned)

        # Normalize whitespace
        tokens = cleaned.split()

        if remove_stopwords:
            tokens = [t for t in tokens if t not in STOPWORDS or t.startswith("[")]

        return " ".join(tokens)

    def find_triggers(self, text: str) -> List[Dict[str, Any]]:
        """
        Identify exact suspicious phrase spans and classifications in original text.
        Returns list of triggers with start/end indices and category.
        """
        if not text:
            return []

        found_triggers = []
        lower_text = text.lower()

        for category, patterns in TRIGGER_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, lower_text, re.IGNORECASE):
                    start, end = match.span()
                    matched_snippet = text[start:end]
                    found_triggers.append({
                        "text": matched_snippet,
                        "category": category,
                        "start": start,
                        "end": end
                    })

        # Also mark standalone suspicious URLs
        for match in self.url_regex.finditer(text):
            start, end = match.span()
            found_triggers.append({
                "text": text[start:end],
                "category": "suspicious_link",
                "start": start,
                "end": end
            })

        # Remove overlaps (keep longer match)
        found_triggers.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
        deduped = []
        last_end = -1
        for trigger in found_triggers:
            if trigger["start"] >= last_end:
                deduped.append(trigger)
                last_end = trigger["end"]

        return deduped

    def compute_heuristic_indicators(self, text: str) -> Dict[str, float]:
        """
        Calculate specialized heuristic indicators:
        - Urgency score (0.0 to 1.0)
        - Financial risk score (0.0 to 1.0)
        - Threat / Impersonation score (0.0 to 1.0)
        - Suspicious Link score (0.0 to 1.0)
        - Capitalization ratio (0.0 to 1.0)
        """
        if not text or len(text.strip()) == 0:
            return {
                "urgency_score": 0.0,
                "financial_score": 0.0,
                "threat_score": 0.0,
                "link_score": 0.0,
                "caps_ratio": 0.0
            }

        lower_text = text.lower()

        def match_count(category: str) -> int:
            count = 0
            for pattern in TRIGGER_PATTERNS.get(category, []):
                count += len(re.findall(pattern, lower_text, re.IGNORECASE))
            return count

        urgency_hits = match_count("urgency")
        financial_hits = match_count("financial")
        threat_hits = match_count("threat")
        phishing_hits = match_count("phishing_action")
        url_count = len(self.url_regex.findall(text))

        # Check for suspicious shortened URLs or IP links
        suspicious_url_flag = 1 if re.search(r"(bit\.ly|tinyurl|t\.co|is\.gd|cutt\.ly|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|-login|\.xyz|\.top|\.ru|\.tk)", lower_text) else 0

        # Capitalization density
        letters = [c for c in text if c.isalpha()]
        caps_count = sum(1 for c in letters if c.isupper())
        caps_ratio = round((caps_count / len(letters)), 3) if letters else 0.0

        urgency_score = min(1.0, urgency_hits * 0.35 + (0.2 if caps_ratio > 0.4 else 0.0))
        financial_score = min(1.0, financial_hits * 0.4)
        threat_score = min(1.0, threat_hits * 0.5)
        link_score = min(1.0, (url_count * 0.3) + (suspicious_url_flag * 0.5) + (phishing_hits * 0.2))

        return {
            "urgency_score": round(urgency_score, 2),
            "financial_score": round(financial_score, 2),
            "threat_score": round(threat_score, 2),
            "link_score": round(link_score, 2),
            "caps_ratio": caps_ratio
        }


# Global helper instance
preprocessor = TextPreprocessor()
