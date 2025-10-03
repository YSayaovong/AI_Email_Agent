/**
 * Gmail Cleaner Agent (safe heuristics, no link opening)
 * Labels created/used:
 *  - Important – Read
 *  - Suspicious – Review
 *  - Processed – GmailCleaner
 *
 * Notes:
 *  - DRY_RUN=true -> never moves to Trash; only labels for review.
 *  - To reprocess a thread, remove the "Processed – GmailCleaner" label from it.
 */

///////////////////////
// CONFIGURATION
///////////////////////

const LABELS = {
  IMPORTANT: "Important – Read",
  SUSPICIOUS: "Suspicious – Review",
  PROCESSED: "Processed – GmailCleaner"
};

// Set to true for a few days to verify behavior safely.
const DRY_RUN = true;

// If you ever want to allow auto-trash, set this true AND DRY_RUN=false.
const HARD_DELETE = false;

// Add your trusted domains or exact emails here.
const KEY_SENDERS = [
  "asu.edu", "fidelity.com", "chase.com", "prosper.com",
  "apartments.com", "intuit.com", "quickbooks.com"
  // Example additions:
  // "schooldistrict.org",
  // "teacher@schooldistrict.org"
];

// Keywords that usually indicate "read me"
const IMPORTANT_KEYWORDS = [
  "invoice", "statement", "payment", "receipt", "past due",
  "action required", "verification code", "2fa", "security alert",
  "job application", "interview", "offer", "schedule", "policy"
];

// Conservative spam heuristics
const SPAM_TLDS = ["ru","cn","su","zip","mov"];
const URL_SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","cutt.ly","rebrand.ly"];
const PHISHING_WORDS = [
  "urgent", "verify your account", "password expired", "unusual activity",
  "click here", "limited time", "suspended", "reset now"
];

// Processing controls
const BATCH_LIMIT = 100; // threads per run

///////////////////////
// ENTRY POINTS
///////////////////////

/** Create labels once */
function setup() {
  ensureLabel(LABELS.IMPORTANT);
  ensureLabel(LABELS.SUSPICIOUS);
  ensureLabel(LABELS.PROCESSED);
  Logger.log("Labels ensured.");
}

/** Main entry: scans Inbox, Spam, Trash (recent first) */
function processMailbox() {
  const queries = [
    'in:inbox -label:"' + LABELS.PROCESSED + '"',
    'in:spam -label:"'  + LABELS.PROCESSED + '"',
    'in:trash -label:"' + LABELS.PROCESSED + '"'
  ];

  for (const q of queries) {
    const threads = GmailApp.search(q, 0, BATCH_LIMIT);
    for (const thread of threads) {
      processThread(thread);
    }
  }
}

///////////////////////
// CORE LOGIC
///////////////////////

/** Thread-level processing */
function processThread(thread) {
  try {
    const messages = thread.getMessages();
    let isImportant = false;
    let isSuspicious = false;
    let isSpam = false;

    for (const msg of messages) {
      const verdict = classifyMessage(msg);
      isImportant  = isImportant  || verdict.important;
      isSuspicious = isSuspicious || verdict.suspicious;
      isSpam       = isSpam       || verdict.spam;
    }

    // Priority: spam > suspicious > important
    if (isSpam && !DRY_RUN) {
      // Gmail permanently deletes after ~30 days in Trash.
      thread.moveToTrash();
    } else if (isSuspicious) {
      thread.addLabel(ensureLabel(LABELS.SUSPICIOUS));
      thread.addStar();
    } else if (isImportant) {
      thread.addLabel(ensureLabel(LABELS.IMPORTANT));
      thread.markImportant();
      thread.addStar();
    }

    // Always mark processed so we don't re-handle the same thread each run
    thread.addLabel(ensureLabel(LABELS.PROCESSED));

  } catch (e) {
    Logger.log("Error processing thread: " + e);
  }
}

/** Message classifier (conservative, link-safe) */
function classifyMessage(msg) {
  const from = (msg.getFrom() || "").toLowerCase();
  const subject = (msg.getSubject() || "").toLowerCase();
  const body = (msg.getPlainBody() || "").toLowerCase(); // no external loads

  const headersAuth = (msg.getHeader("Authentication-Results") || "").toLowerCase();
  const replyTo = (msg.getReplyTo() || "").toLowerCase();

  const senderDomain = extractDomain(from);
  const replyDomain  = extractDomain(replyTo);

  const hasSPFPass  = headersAuth.includes("spf=pass");
  const hasDKIMPass = headersAuth.includes("dkim=pass");

  const urls = extractUrls(body);
  const hasShorteners = urls.some(u => URL_SHORTENERS.some(s => u.includes(s)));
  const hasWeirdTld = senderDomain && SPAM_TLDS.some(tld => senderDomain.endsWith("." + tld));

  const urgentTone = PHISHING_WORDS.some(w => subject.includes(w) || body.includes(w));
  const keywordImportant = IMPORTANT_KEYWORDS.some(w => subject.includes(w) || body.includes(w));
  const knownSender = isKnownSender(from, senderDomain);

  const domainMismatch = senderDomain && replyDomain && senderDomain !== replyDomain;

  // Spam (only if NOT known sender)
  const spamScore = (!knownSender && (
    hasWeirdTld ||
    (hasShorteners && urgentTone) ||
    (!hasSPFPass && !hasDKIMPass && urgentTone && urls.length > 0)
  ));

  // Suspicious (softer; SPF/DKIM fail alone is not enough)
  const suspiciousScore = (!spamScore && !knownSender && (
    domainMismatch ||
    (urgentTone && urls.length > 0)
  ));

  // Important
  const importantScore = (knownSender ||
    (keywordImportant && (hasSPFPass || hasDKIMPass))
  );

  return {
    spam: spamScore && !importantScore,
    suspicious: !spamScore && suspiciousScore && !importantScore,
    important: importantScore
  };
}

///////////////////////
// UTILITIES
///////////////////////

function ensureLabel(name) {
  const existing = GmailApp.getUserLabels().find(l => l.getName() === name);
  return existing || GmailApp.createLabel(name);
}

function extractDomain(addr) {
  const m = addr.match(/[<\s]([a-z0-9._%+-]+)@([a-z0-9.-]+\.[a-z]{2,})[>\s]?/i);
  return m ? m[2].toLowerCase() : "";
}

function extractUrls(text) {
  const re = /\bhttps?:\/\/[^\s)>'"]+/gi;
  const matches = text.match(re) || [];
  return matches.map(u => u.toLowerCase());
}

// Accepts either exact email ("user@domain.com") or domain ("domain.com")
function isKnownSender(from, senderDomain) {
  if (!from && !senderDomain) return false;
  return KEY_SENDERS.some(sd => {
    const s = sd.toLowerCase().trim();
    if (!s) return false;
    if (s.includes("@")) {
      // exact email match
      return from.includes(s);
    }
    // domain match (endsWith to cover subdomains)
    return senderDomain.endsWith(s);
  });
}
