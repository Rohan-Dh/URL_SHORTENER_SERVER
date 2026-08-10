import { contentFilterLogger } from '../utils/logger.js';

/**
 * URL Shortener Content Filter
 *
 * Ported from NestSMS's SMS message content filter, trimmed to what a
 * public, no-login URL shortener needs. Runs against
 * `${alias ?? ''} ${url}` at creation time — one call covers both the
 * alias/title text (profanity, scam wording) and the destination URL
 * (phishing/adult/gambling domain checks).
 *
 * Removed from the SMS original (see NEST_SMS_URL_WEB build plan for the
 * full reasoning):
 *   - The OTP template system (otp_no_template/otp_messages rules,
 *     redaction, template-verification helpers) — no such concept here.
 *   - SMS-conversation-only categories (threats, self-harm, harassment,
 *     child safety, extremism, weapons, drugs, doxxing) — these detect
 *     abusive things people say to each other in a message body, not
 *     something that shows up in a URL or a short alias.
 *   - SimHash near-duplicate detection — two people shortening the same
 *     popular URL isn't spam here.
 *   - The "any non-allowlisted link ⇒ REVIEW" rule — the entire input to
 *     this filter IS a link, so that rule would flag nearly everything.
 *   - The REVIEW tier itself. There's no moderation queue in this product,
 *     so `Decision` is just PASS | BLOCK: anything that used to be
 *     REVIEW-worthy (profanity, adult content, gambling, scam/fraud
 *     wording, a domain typosquatting a known brand, a high phishing
 *     composite score) now blocks outright. A merely suspicious TLD
 *     (.xyz, .top, …) alone still does NOT block — too many legitimate
 *     sites use them for that to be fair evidence on its own.
 *
 * Kept: normalisation, the profanity trie, the URL/domain phishing
 * pipeline (homoglyph + typosquat + shortener-chain + suspicious-TLD
 * classification, known adult/gambling domain lists), brand-spoof
 * detection, the phishing signal combiner, and per-IP rate limiting.
 */

// ─────────────────────────────────────────────────────────────────────────────
// TYPE DEFINITIONS
// ─────────────────────────────────────────────────────────────────────────────

export type Decision = 'PASS' | 'BLOCK';
export type MatchedOn = 'original' | 'normalised' | 'normalised-words' | 'trie' | 'url' | 'signals' | 'spam' | null;

export interface CheckResult {
  decision: Decision;
  ruleId: string | null;
  category: string | null;
  matchedOn: MatchedOn;
  riskScore: number;
  triggers: string[];
  meta: Record<string, unknown>;
}

interface TopRule {
  id: string;
  category: string;
  matchedOn: MatchedOn;
  score: number;
}

interface TrieNode {
  children: Map<string, TrieNode>;
  fail: TrieNode | null;
  outputs: string[];
}

interface TrieHit {
  word: string;
  index: number;
}

interface URLLink {
  host: string;
  allowed: boolean;
  shortener: boolean;
  reason: string | null;
}

interface URLCheckResult {
  flagged: boolean;
  domains: string[];
  reason: string | null;
  links: URLLink[];
  hasUnknownLink: boolean;
  hasShortener: boolean;
}

interface BrandHit {
  brand: string;
  spoofed: boolean;
  as: string;
}

interface PhishingScore {
  score: number;
  triggers: string[];
  brandHit: BrandHit | null;
}

interface RateBucket {
  count: number;
  windowStart: number;
}

export interface FilterOptions {
  /** Requester identifier for rate limiting — an IP address in practice. */
  identifier?: string;
}

export interface ContentPolicyResponse {
  error: string;
  code: string;
  category: string | null;
  ruleId: string | null;
  riskScore: number | null;
}

export interface AuditEntry {
  ts: string;
  identifier: string;
  decision: Decision;
  riskScore: number;
  ruleId: string | null;
  category: string | null;
  matchedOn: MatchedOn;
  triggers: string[];
  meta: Record<string, unknown>;
  contentLen: number;
  excerpt: string;
}

export interface FilterResult {
  result: CheckResult;
  response: ContentPolicyResponse | null;
  audit: AuditEntry | null;
}

export interface ContentFilterLogContext {
  ip?: string;
  userAgent?: string;
  endpoint?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// 0. CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Single reject threshold (was THRESHOLD_REVIEW in the SMS filter — the
 * "a human should look at this" bar). With no moderation queue to send
 * borderline content to, this is now the outright reject bar.
 */
const THRESHOLD_BLOCK = 0.35;

/**
 * Categories that can actually reject a shorten request. Everything else
 * (a bare mention of a bank name, a suspicious-but-not-spoofed TLD, a lone
 * link shortener) is too weak on its own for an unattended public tool to
 * refuse a URL over.
 */
const BLOCK_CATEGORIES = new Set(['profanity', 'adult_content', 'gambling', 'scam_or_fraud', 'phishing_url']);

const CATEGORY_WEIGHTS = {
  profanity: 0.9,
  adult_content: 0.85,
  scam_or_fraud: 0.95,
  financial_entity: 0.6,
  phishing_url: 0.95,
  spam_duplicate: 0.7,
  gambling: 0.65,
} as const;

type CategoryKey = keyof typeof CATEGORY_WEIGHTS;

interface Rule {
  id: string;
  category: CategoryKey;
  level: 2 | 3;
  confidence: number;
  patterns: RegExp[];
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. NORMALISATION
// ─────────────────────────────────────────────────────────────────────────────

const HOMOGLYPH_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '6': 'g',
  '7': 't',
  '8': 'b',
  '9': 'q',
  '@': 'a',
  '!': 'i',
  $: 's',
  '+': 't',
  '|': 'i',
  '(': 'c',
  ')': 'o',
  '<': 'c',
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  ь: 'b',
  і: 'i',
  ѕ: 's',
  ӏ: 'l',
  α: 'a',
  ε: 'e',
  ο: 'o',
  υ: 'u',
  '​': '',
  '‌': '',
  '‍': '',
  '﻿': '',
  '­': '',
  '͏': '',
};

const HOMOGLYPH_RE = new RegExp(
  '[' +
    Object.keys(HOMOGLYPH_MAP)
      .map((c) => c.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&'))
      .join('') +
    ']',
  'g',
);

export function normalise(text: string): string {
  return text
    .normalize('NFC')
    .toLowerCase()
    .replace(HOMOGLYPH_RE, (ch) => HOMOGLYPH_MAP[ch] ?? ch)
    .replace(/[\s._\-*/\\|,;:'"!?]+/g, '');
}

export function normaliseWords(text: string): string {
  return text
    .normalize('NFC')
    .toLowerCase()
    .replace(HOMOGLYPH_RE, (ch) => HOMOGLYPH_MAP[ch] ?? ch)
    .replace(/[\s._\-*/\\|,;:'"!?]+/g, ' ')
    .trim();
}

export function normaliseForTrie(text: string): string {
  const MINIMAL_HOMOGLYPH_MAP: Record<string, string> = {
    а: 'a',
    е: 'e',
    о: 'o',
    р: 'p',
    с: 'c',
    у: 'y',
    х: 'x',
    ь: 'b',
    і: 'i',
    ѕ: 's',
    ӏ: 'l',
    α: 'a',
    ε: 'e',
    ο: 'o',
    υ: 'u',
  };
  const MINIMAL_RE = new RegExp(
    '[' +
      Object.keys(MINIMAL_HOMOGLYPH_MAP)
        .map((c) => c.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&'))
        .join('') +
      ']',
    'g',
  );

  return text
    .normalize('NFC')
    .toLowerCase()
    .replace(MINIMAL_RE, (ch) => MINIMAL_HOMOGLYPH_MAP[ch] ?? ch)
    .replace(/[\s._\-*/\\|,;:'"!?()[\]{}]+/g, ' ')
    .trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. AHO-CORASICK TRIE
// ─────────────────────────────────────────────────────────────────────────────

class AhoCorasick {
  private _root: TrieNode;

  constructor(words: string[]) {
    this._root = this._newNode();
    for (const w of words) this._insert(w);
    this._buildFail();
  }

  private _newNode(): TrieNode {
    return { children: new Map(), fail: null, outputs: [] };
  }

  private _insert(word: string): void {
    let node = this._root;
    for (const ch of word) {
      if (!node.children.has(ch)) node.children.set(ch, this._newNode());
      node = node.children.get(ch)!;
    }
    node.outputs.push(word);
  }

  private _buildFail(): void {
    const queue: TrieNode[] = [];
    for (const [, child] of this._root.children) {
      child.fail = this._root;
      queue.push(child);
    }
    let i = 0;
    while (i < queue.length) {
      const curr = queue[i++]!;
      for (const [ch, child] of curr.children) {
        let fail = curr.fail;
        while (fail && !fail.children.has(ch)) fail = fail.fail;
        child.fail = fail ? (fail.children.get(ch) ?? this._root) : this._root;
        if (child.fail === child) child.fail = this._root;
        child.outputs = [...child.outputs, ...child.fail.outputs];
        queue.push(child);
      }
    }
  }

  search(text: string): TrieHit[] {
    const results: TrieHit[] = [];
    let node = this._root;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;
      while (node !== this._root && !node.children.has(ch)) node = node.fail!;
      if (node.children.has(ch)) node = node.children.get(ch)!;
      for (const word of node.outputs) {
        results.push({ word, index: i - word.length + 1 });
      }
    }
    return results;
  }
}

const EXACT_BLOCKLIST: string[] = [
  // English profanity — full forms (leet already collapsed by normalise())
  'fuck',
  'fucker',
  'fucking',
  'motherfucker',
  'shit',
  'shitty',
  'bitch',
  'bitches',
  'asshole',
  'ass',
  'cunt',
  'prick',
  'dick',
  'cock',
  'pussy',
  'whore',
  'slut',
  'bastard',
  'douchebag',
  'dumbass',
  'nigger',
  'faggot',
  'jackass',
  'dipshit',
  'horseshit',
  'bullshit',
  'chickenshit',
  'shithead',
  'shitstain',
  'fuckhead',
  'fuckwit',
  'fuckface',
  'fucktard',
  'fuckboy',
  'fuckgirl',
  'clusterfuck',
  'mindfuck',
  'asswipe',
  'assclown',
  'assbag',
  'assmunch',
  'asslicker',
  'butthole',
  'butthead',
  'butt-fuck',
  'turd',
  'cumshot',
  'cumslut',
  'cumrag',
  'jizz',
  'spunk',
  'skank',
  'skanky',
  'tramp',
  'trollop',
  'harlot',
  'strumpet',
  'jezebel',
  'twat',
  'minge',
  'bellend',
  'knobhead',
  'wanker',
  'tosser',
  'bollocks',
  'arsehole',
  'arse',
  'bugger',
  'blighter',
  'spastic',
  'mong',
  'gimp',
  'cretin',
  'imbecile',
  'moron',
  'numbnuts',
  'dickhead',
  'dickwad',
  'dickweed',
  'dickface',
  'penisface',
  'vagface',
  'taintface',
  'scrotum',
  'shitbag',
  'shithole',
  'shithouse',
  'shitfaced',
  'pissbag',
  'pisshead',
  'pissface',
  'tard',
  'libtard',
  'conservatard',
  'feminazi',
  'kike',
  'spic',
  'chink',
  'gook',
  'wetback',
  'cracker',
  'honkey',
  'coon',
  'darkie',
  'nig',
  'nigs',
  'paki',
  'raghead',
  'towelhead',
  'sandnigger',
  'camel-jockey',
  'dyke',
  'tranny',
  'shemale',
  'ladyboy',

  // Consonant-skeleton evasion forms
  'fck',
  'fuk',
  'sht',
  'btch',
  'cnt',
  'pck',
  'dck',
  'cck',
  'psy',
  'whr',
  'slt',
  'bstrd',
  'ngr',
  'fgt',
  'jckss',
  'bllsht',
  'fkng',
  'mthfkr',
  'wnkr',
  'tssr',
  'bllnds',
  'rshle',
  'dckd',
  'dckwd',
  'dckfc',

  // Romanised Nepali/Hindi
  'madarchod',
  'benchod',
  'bhenchod',
  'chutiya',
  'lund',
  'loda',
  'gandu',
  'randi',
  'harami',
  'haramzada',
  'bhosadike',
  'chod',
  'kutte',
  'kutti',
  'muji',
  'boksi',
  'sala',
  'sali',
  'kamina',
  'kamini',
  'lafanga',
  'pagal',
  'bhosdike',
  'bhosdiwale',
  'bhosdika',
  'bhosdiki',
  'maa ki aankh',
  'maa ka',
  'teri maa',
  'teri behen',
  'behenchod',
  'behen ke lode',
  'behen ki',
  'bhen ke',
  'saale',
  'saali',
  'kameena',
  'kameeni',
  'ullu',
  'ullukapattha',
  'gadha',
  'gadhi',
  'suar',
  'suarke',
  'suarki',
  'bakri',
  'raand',
  'randi rona',
  'randibazi',
  'besharam',
  'besharmi',
  'nalayak',
  'nakara',
  'nikamma',
  'dhokha',
  'dhokhebaaz',
  'kanjoos',
  'haramkhor',
  'haramkhori',
  'haramipana',
  'dalal',
  'dalali',
  'pimp',
  'chakka',
  'hijra',
  'hijron',
  'kinner',
  'napunsak',
  'bawasir',
  'chutad',
  'gaand mara',
  'gaand maar',
  'lund chus',
  'loda chus',
  'chut maar',
  'teri gand',
  'meri gand',
  'gand mein',
  'tatte',
  'tattewala',
  'phuddi',
  'fuddi',
  'bur',
  'burand',
  'lundbaaz',
  'randikhana',
  'maa chod',
  'baap chod',
  'bap ka',
  'baap ka',
  'mujiko',
  'mujikhane',
  'laato',
  'laathi',
  'gadha muji',
  'kukur',
  'kukurko',
  'kukurki',
  'suarko',
  'suarki',
  'bhutuwa',
  'bhutni',
  'puti',
  'putiko',
  'raandiko',
  'randibaazi',
  'jhata',
  'jhatako',
  'jhataki',
  'phutti',
  'chikne',
  'chikni',
  'chikna',
  'lure',
  'lurey',
  'lureko',
  'tharke',
  'tharki',
  'tharkipana',
  'bhanda',
  'bhandako',
  'bhandaki',
  'haram',
  'haramzade',
  'kutteko',
  'kuttebacha',
  'saaley',
  'saaleyko',
  'saaliyo',
  'nalayakko',
  'nikammako',
  'dhoti',
  'dhotiko',
  'pahaade',
  'madhise',
  'bahun',
  'chhetri',
  'dalit-gaali',

  // Common scam triggers
  'ponzi',
  'pyramid',
];

const BLOCKLIST_TRIE = new AhoCorasick(EXACT_BLOCKLIST);

// ─────────────────────────────────────────────────────────────────────────────
// 3. REGEX RULE REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

const RULES: Rule[] = [
  {
    id: 'profanity_en',
    category: 'profanity',
    level: 3,
    confidence: 0.85,
    patterns: [
      /\bf+u+c+k+(e[rd]|ing|s|er)?\b/i,
      /\bmother[\W_]*f+u+c+k/i,
      /\bs+h+i+t+(ty)?\b/i,
      /\bb+i+t+c+h+(e[sd]|ing)?\b/i,
      /\ba+s+s+h+o+l+e+\b/i,
      /\ba+s+s+(hat|wipe|bag)?\b/i,
      /\bc+u+n+t+\b/i,
      /\bp+r+i+c+k+\b/i,
      /\bd+i+c+k+\b/i,
      /\bc+o+c+k+\b/i,
      /\bp+u+s+s+y+\b/i,
      /\bw+h+o+r+e+\b/i,
      /\bs+l+u+t+(ty)?\b/i,
      /\bb+a+s+t+a+r+d+\b/i,
      /\bdouche(bag)?\b/i,
      /\bdumbass\b/i,
      /\bretard(ed)?\b/i,
      /\bn[i1!]+g+[ae]+r?\b/i,
      /\bf[a@]+g+(g+o+t+)?\b/i,
      /\bj[a@]+ck[\W_]*a+s+s+\b/i,
      /\bb[u]+ll[\W_]*sh[i]+t+\b/i,
      /\bh[o]+rs+e[\W_]*sh[i]+t+\b/i,
      /\bch[i]+ck+en[\W_]*sh[i]+t+\b/i,
      /\bsh[i]+t+h[e]+[a@]+d+\b/i,
      /\bsh[i]+t+st[a@]+[i]+n+\b/i,
      /\bf+u+ck+h[e]+[a@]+d+\b/i,
      /\bf+u+ck+w[i]+t+\b/i,
      /\bf+u+ck+f[a@]+c[e]+\b/i,
      /\bf+u+ck+t[a@]+r+d+\b/i,
      /\bf+u+ck+b[o0]+y+\b/i,
      /\bc+l+u+st+e+r+f+u+ck+\b/i,
      /\ba+ss+w[i]+p+e+\b/i,
      /\ba+ss+cl+[o0]+w+n+\b/i,
      /\ba+ss+m+u+n+ch+\b/i,
      /\bb+u+tt+h+[o0]+l+e+\b/i,
      /\bb+u+tt+h+[e]+[a@]+d+\b/i,
      /\bt+u+r+d+\b/i,
      /\bs+k+[a@]+n+k+(y+)?\b/i,
      /\bt+r+[a@]+m+p+\b/i,
      /\bh+[a@]+r+l+[o0]+t+\b/i,
      /\bt+w+[a@]+t+\b/i,
      /\bb+[e]+ll+[e]+n+d+\b/i,
      /\bkn+[o0]+bh+[e]+[a@]+d+\b/i,
      /\bw+[a@]+n+k+[e]+r+\b/i,
      /\bt+[o0]+ss+[e]+r+\b/i,
      /\bb+[o0]+ll+[o0]+ck+s+\b/i,
      /\b[a@]+r+s+[e]+h+[o0]+l+e+\b/i,
      /\b[a@]+r+s+[e]+\b/i,
      /\bb+u+gg+[e]+r+\b/i,
      /\bsp+[a@]+st+[i]+c+\b/i,
      /\bg+[i]+m+p+\b/i,
      /\bd+[i]+ck+h+[e]+[a@]+d+\b/i,
      /\bd+[i]+ck+w+[a@]+d+\b/i,
      /\bd+[i]+ck+w+[e]+[e]+d+\b/i,
      /\bn+[i1]+gg+[e]+r+\b/i,
      /\bk+[i1]+k+[e]+\b/i,
      /\bsp+[i1]+c+\b/i,
      /\bch+[i1]+nk+\b/i,
      /\bg+[o0]+[o0]+k+\b/i,
      /\bp+[a@]+k+[i1]+\b/i,
      /\br+[a@]+gh+[e]+[a@]+d+\b/i,
      /\bs+[a@]+n+d+n+[i1]+gg+[e]+r+\b/i,
      /\bd+y+k+[e]+\b/i,
      /\btr+[a@]+nn+y+\b/i,
      /\bsh+[e]+m+[a@]+l+[e]+\b/i,
      /\bl+[a@]+d+y+b+[o0]+y+\b/i,
      /\bf+[e]+m+[i1]+n+[a@]+z+[i1]+\b/i,
    ],
  },
  {
    id: 'profanity_hi_ne',
    category: 'profanity',
    level: 3,
    confidence: 0.85,
    patterns: [
      /\bm[a@]+d[a@]+r[\W_]*ch[o0]+d\b/i,
      /\bbh[e3]+n[\W_]*ch[o0]+d\b/i,
      /\bch[u]+t(iy[a@])?\b/i,
      /\bl[u]+nd\b/i,
      /\bl[o0]+d[a@]\b/i,
      /\bg[a@]+nd[u]?\b/i,
      /\bg[a@]+[a@]+nd\b/i,
      /\br[a@]+nd[iy]\b/i,
      /\bh[a@]+r[a@]+m(i|z[a@]+d[a@])\b/i,
      /\bbh[o0]+sd[iy]k[ae]\b/i,
      /\bch[o0]+d[u]?\b/i,
      /\bt[a@]+tt[iy]\b/i,
      /\bk[u]+tt[a@i]\b/i,
      /\bm[u]+j[i]+\b/i,
      /\bm[u]+g[i]+\b/i,
      /\bboks[iy]+\b/i,
      /\bs[a@]+[a@]+l[ai]\b/i,
      /\bk[a@]+m[i]+n[ai]\b/i,
      /\bl[a@]+f[a@]+ng[a@]\b/i,
      /\bp[a@]+g[a@]+l\b/i,
      /\bp[a@]+kh[e]+\b/i,
      /\bkh[a@]+t[e]+\b/i,
      /\bt[e]+r[i]+\s*(m[a@]+[a@]|b[e]+h[e]+n)\b/i,
      /\bm[a@]+[a@]\s*k[i]+\s*(aa+nkh|ch[u]+t)\b/i,
      /\bb[e]+h[e]+n[\W_]*(ch[o0]+d|k[e]+\s*l[o0]+d[e]+)\b/i,
      /\bs[a@]+[a@]+l[e]+\b/i,
      /\bk[a@]+m[e]+[e]+n[ai]\b/i,
      /\bu+ll+[u]+\b/i,
      /\bg[a@]+dh[a@i]\b/i,
      /\bs+u[a@]+r+(ke|ki)?\b/i,
      /\br[a@]+[a@]+nd+(ib[a@]+z[i]+|ron[a@]?)?\b/i,
      /\bn[a@]+l[a@]+y[a@]+k+\b/i,
      /\bh[a@]+r[a@]+mk+h[o0]+r+\b/i,
      /\bd[a@]+l[a@]+l+(i+)?\b/i,
      /\bch[a@]+kk[a@]\b/i,
      /\bh[i]+jr[a@]\b/i,
      /\bn[a@]+p[u]+ns[a@]+k+\b/i,
      /\bg[a@]+[a@]+nd[\W_]*(m[a@]+r[a@]|m[e]+[i]+n)\b/i,
      /\bl[u]+nd[\W_]*ch[u]+s+\b/i,
      /\bt[a@]+tt[e]+w[a@]+l[a@]\b/i,
      /\bf[u]+dd[i]+\b/i,
      /\bp[hu]+dd[i]+\b/i,
      /\bb+[u]+r[\W_]*(m[e]+[i]+n|w[a@]+l[a@])?\b/i,
      /\br[a@]+nd[i]+kh[a@]+n[a@]\b/i,
      /\bm[a@]+[a@]\s*ch[o0]+d+\b/i,
      /\bb[a@]+[a@]+p[\W_]*ch[o0]+d+\b/i,
      /\bth[a@]+rk[i]+\b/i,
      /\bl[u]+r[e]+y?\b/i,
      /\bch[i]+kn[e]+\b/i,
      /मादरचोद|मदरचोद|माचिक्ने/,
      /रण्डी|रंडी|रन्डी|छिनाल/,
      /हरामी|हरामजादा/,
      /लण्ड|लन्ड|लोडा/,
      /चुत|चोद|चोदु/,
      /मुजी|मूजी|मुगि|मूगी/,
      /गाँड|गाण्ड|गांड|गान्डु|गान्ड/,
      /भाँडु|भाडु|बोक्सी/,
      /हिजडा|हिजड़ा/,
      /कमिना|कमिनी/,
      /कुत्ता|कुत्ती/,
      /साला|साली|दलाल|लफंगा|लफङ्गा|पाजी/,
      /धन्दा\s*गर्ने|देहव्यापार/,
      /पाखे|पाक्ने|खाते|धोती|गधा|गधो/,
    ],
  },
  {
    id: 'profanity_devanagari_extended',
    category: 'profanity',
    level: 3,
    confidence: 0.9,
    patterns: [
      /तेरी\s*(माँ|मा|बहन)/,
      /माँ\s*की\s*(आँख|चुत)/,
      /बहन\s*(चोद|के\s*लोडे)/,
      /साले|कमीने|कमीनी/,
      /उल्लू(का\s*पट्ठा)?/,
      /गधा|गधी|सूअर/,
      /नालायक|निकम्मा|हरामखोर/,
      /दलाल|चक्का|हिजड़ा|नपुंसक/,
      /गांड\s*(मार|में)/,
      /लंड\s*चूस/,
      /रंडीखाना|तत्तेवाला/,
      /थरकी|लुरे|चिकने/,
      /माँ\s*चोद|बाप\s*चोद/,
      /मुजीखाने|लाटो|गधा\s*मुजी/,
      /कुकुर(को|की)?|सुँगुर(को|की)?/,
      /भुतुवा|भूतनी/,
      /पुटी(को)?|झट्टा(को)?/,
      /रण्डीबाजी|लण्डबाज/,
      /थर्की|भण्डा(को)?/,
      /धोती(को)?|पहाडे|मधिसे/,
      /छिनाल(को|ले)?|जारी(को)?/,
      /हलुवा|पाजी|ठग|ठगी/,
      /बदमास|बदमासी|लुच्चा|लुच्ची/,
      /लम्पट|लम्पटी|चरित्रहीन/,
      /कुलटा|वेश्या|देहव्यापारी/,
    ],
  },
  {
    id: 'adult_content',
    category: 'adult_content',
    level: 3,
    confidence: 0.85,
    patterns: [
      /\bporn(ography|ographic)?\b/i,
      /\bxxx\b/i,
      /\bnude(s)?\b/i,
      /\bsex\s+(video|clip|tape|photo|pic|image)\b/i,
      /\bsex\s+worker\b/i,
      /\bescort\s+service\b/i,
      /\bcall\s+girl\b/i,
      /\bprostitut(e|ion)\b/i,
      /\bonlyfans\b/i,
      /अश्लील/,
      /नाङ्गो|नांगो/,
      /यौन\s*(भिडियो|तस्बिर|फोटो|सम्बन्ध)/,
      /सेक्स\s*(भिडियो|तस्बिर|फोटो)/,
      /यौनकर्मी/,
    ],
  },
  {
    id: 'gambling',
    category: 'gambling',
    level: 2,
    confidence: 0.65,
    patterns: [
      /\b(online\s+(casino|gambling|betting|poker|slots))\b/i,
      /\b(sports\s+(bet(ting)?|wager(ing)?))\b/i,
      /\b(place\s+(a\s+)?bet|place\s+(your\s+)?wager)\b/i,
      /\b(bet\s+\$?\d+\s+on)\b/i,
      /\b(win\s+(big|jackpot)\s+(at|in|on)\s+(casino|slots|poker|roulette))\b/i,
      /\b(free\s+(spins|chips|bets)\s+(at|on|in)\s+casino)\b/i,
      /\b(deposit\s+bonus\s+(at|on)\s+casino)\b/i,
      /\b(cricket\s+(satta|betting)|ipl\s+satta|ipl\s+betting)\b/i,
      /\b(satta\s+(matka|bazar|king|result))\b/i,
      /सट्टा\s*(खेल्नुस्|लगाउनुस्|बेट)/,
      /जुवा\s*(खेल्नुस्|खेल्छु|खेल)\b/,
      /अनलाइन\s*(क्यासिनो|जुवा|सट्टा)/,
    ],
  },
  {
    id: 'spam_phrases',
    category: 'spam_duplicate',
    level: 2,
    confidence: 0.55,
    patterns: [
      /\b(act\s+now|limited\s+time\s+(offer|deal)|offer\s+expires|don'?t\s+miss\s+out)\b/i,
      /\b(click\s+(here|now|below|this\s+link)\s+(to\s+)?(claim|get|access|download|buy|sign\s+up))\b/i,
      /\b(you\s+have\s+been\s+(selected|chosen|picked)\s+(as\s+a\s+)?winner)\b/i,
      /\b(congratulations?\s+(you('ve|\s+have)\s+won|you\s+are\s+(a\s+)?(winner|lucky)))\b/i,
      /\b(this\s+is\s+not\s+(a\s+)?scam|i\s+(swear|promise)\s+it('s|\s+is)\s+(real|legit|genuine))\b/i,
      /\b(send\s+this\s+to\s+(all|every|your)\s+(contacts|friends|group)s?\s+(for\s+(good\s+luck|blessings?|a\s+miracle)))\b/i,
      /\b(forward\s+to\s+\d+\s+(friends|people|contacts)\s+(within|in)\s+\d+\s+(minutes?|hours?))\b/i,
      /\b(earn\s+(money\s+)?(while\s+you\s+sleep|without\s+(work|effort|experience)))\b/i,
      /\b(secret\s+(method|trick|hack)\s+(to\s+)?(earn|make|get)\s+\$?\d+)\b/i,
      /\b(unsubscribe|opt[\W_]*out|remove\s+me\s+from\s+(this\s+)?list)\b/i,
      /\b(this\s+(message\s+)?will\s+(self[\W_]*destruct|expire\s+in\s+\d+))\b/i,
      /यो\s*सन्देश\s*सबैलाई\s*(पठाउनुस्|फर्वार्ड\s*गर्नुस्)/,
      /\d+\s*(जनालाई|मान्छेलाई)\s*पठाए\s*(राम्रो|शुभ|भाग्य)/,
      /अहिले\s*(नै\s*)?(क्लिक|सम्पर्क|फोन)\s*गर्नुस्/,
      /सीमित\s*समयको\s*अफर/,
      /निःशुल्क\s*(प्राप्त\s*गर्नुस्|लिनुस्|दिइँदैछ)/,
    ],
  },
  {
    id: 'scam_fraud_hard',
    category: 'scam_or_fraud',
    level: 3,
    confidence: 0.9,
    patterns: [
      /\b(you('ve| have))?\s*won\s+(a\s+)?(cash\s+)?prize\b/i,
      /\bclaim\s+your\s+(prize|reward|gift|winnings)\b/i,
      /\b(free\s+)?lottery\s+(winner|won|prize)\b/i,
      /\bsend\s+(your\s+)?(bank|credit\s+card|account)\s+(details|info(rmation)?|number)\b/i,
      /\bpyramid\s+scheme\b/i,
      /\b100\s*%\s*(profit|return|guaranteed)\b/i,
      /\bdouble\s+your\s+money\b/i,
      /\bponzi\b/i,
      /\benter\s+your\s+password\b/i,
      /\bverify\s+your\s+(account|bank|card)\s+(now|immediately|urgently)\b/i,
      /\bwire\s+transfer\s+(fee|advance)\b/i,
      /\badvance\s+(fee|payment)\s+required\b/i,
      /\burgent\s+(bank\s+)?transfer\b/i,
      /पुरस्कार\s*जित्नुभयो|पुरस्कार\s*पाउनुभयो|नगद\s*जित्नुभयो|लटरी\s*जित्नुभयो/,
      /पैसा\s*पठाउनुस्|अग्रिम\s*शुल्क/,
      /बैंक\s*खाता\s*नम्बर\s*पठाउनुस्/,
      /पासवर्ड\s*दिनुस्|पासवर्ड\s*पठाउनुस्/,
      /खाता\s*प्रमाणित\s*गर्नुस्/,
      /\b(account\s+)?suspended\s+(unless|until)\s+you\s+verify\b/i,
      /\bunusual\s+(sign-?in|login|activity)\s+detected\b/i,
      /\bclick\s+(here|below|this\s+link)\s+to\s+(verify|confirm|restore|secure)\b/i,
      /\b(guaranteed\s+(daily|weekly|monthly)\s+(profit|return|income))\b/i,
      /\b(passive\s+income\s+(of\s+)?\d+[\W_]*(percent|%))\b/i,
      /\b(invest\s+(just\s+)?\$?\d+\s+and\s+(earn|get|make)\s+\$?\d+)\b/i,
      /\b(high[\W_]*(yield|return)\s+investment\s+(program|scheme|plan)?)\b/i,
      /\b(hyip|ponzi|pyramid|mlm\s+scheme)\b/i,
      /\b(forex\s+(signal|trading\s+group|bot|managed\s+account))\b/i,
      /\b(crypto\s+(recovery|doubler|multiplier|signal|pump\s+group))\b/i,
      /\b(bitcoin\s+(doubler|generator|miner\s+for\s+hire))\b/i,
      /\b(nft\s+(giveaway|free\s+mint|whitelist\s+spot\s+for\s+sale))\b/i,
      /\b(referral\s+(bonus|scheme)\s+(earn|get)\s+\$?\d+\s+per\s+(friend|person|referral))\b/i,
      /\b(work\s+from\s+home\s+(earn|make)\s+\$?\d+\s+(per\s+(day|hour|week)))\b/i,
      /\b(make\s+money\s+(online\s+)?(fast|quickly|overnight|in\s+\d+\s+(days|hours)))\b/i,
      /\b(get\s+rich\s+quick)\b/i,
      /\b(data\s+entry\s+job\s+(earn|make)\s+\$?\d+)\b/i,
      /\b(typing\s+job\s+(from\s+home\s+)?(earn|make)\s+\$?\d+)\b/i,
      /\b(part[\W_]*time\s+(earn|make)\s+\$?\d+\s+per\s+(day|hour))\b/i,
      /\b(no\s+experience\s+(needed|required)\s+(earn|make)\s+\$?\d+)\b/i,
      /\b(registration\s+fee\s+required\s+to\s+(start|begin|apply))\b/i,
      /\b(pay\s+(a\s+)?(small\s+)?fee\s+to\s+(unlock|access|start|begin|apply))\b/i,
      /\b(send\s+(me\s+)?(your\s+)?(passport|citizenship|national\s+id|voter\s+id)\s+(number|copy|photo|scan|image))\b/i,
      /\b(photo\s+of\s+(your\s+)?(passport|citizenship|driving\s+licence|national\s+id))\b/i,
      /\b(verify\s+(your\s+)?(identity|id)\s+(by\s+)?(sending|uploading|providing)\s+(a\s+)?photo)\b/i,
      /\b(social\s+security\s+number|ssn|pan\s+card\s+number)\b/i,
      /\b(i\s+have\s+(a\s+)?video\s+of\s+you\s+(masturbating|naked|having\s+sex))\b/i,
      /\b(pay\s+(me|us)\s+(or|otherwise|else)\s+i('ll|\s+will)\s+send\s+(the\s+video|it)\s+to)\b/i,
      /\b(your\s+(contacts|friends|family)\s+will\s+(see|receive)\s+(this|the\s+(video|photo)))\b/i,
      /\b(काम\s*गरेर)\s*(दैनिक|साप्ताहिक)\s*\d+\s*(कमाउनुस्|पाउनुस्)\b/,
      /घरबाटै\s*काम\s*(गरेर)?\s*\d+\s*कमाउनुस्/,
      /लगानी\s*(गर्नुस्|गरेर)\s*\d+\s*(प्रतिशत|%)\s*(प्रतिफल|नाफा)/,
      /पासपोर्ट\s*(नम्बर|फोटो|कपि)\s*पठाउनुस्/,
      /नागरिकता\s*(नम्बर|फोटो|कपि)\s*पठाउनुस्/,
      /भिडियो\s*छ\s*(तपाईंको|तिम्रो)\s*(नाङ्गो|अश्लील)/,
      /पैसा\s*नपठाए\s*(भिडियो|फोटो)\s*(भाइरल|सार्वजनिक)/,
      /रेफरल\s*(बोनस|कमिसन)\s*\d+\s*(रुपैयाँ|रु\.?)/,
    ],
  },
  {
    id: 'financial_entities',
    category: 'financial_entity',
    level: 2,
    confidence: 0.65,
    patterns: [
      /nabil\s*bank/i,
      /global\s*ime\s*bank/i,
      /nic\s*asia\s*bank/i,
      /nepal\s*investment\s*mega\s*bank/i,
      /standard\s*chartered\s*bank\s*nepal/i,
      /himalayan\s*bank/i,
      /everest\s*bank/i,
      /nepal\s*sbi\s*bank/i,
      /nepal\s*bank\s*limited/i,
      /rastriya\s*banijya\s*bank/i,
      /agricultural\s*development\s*bank/i,
      /kumari\s*bank/i,
      /machhapuchchhre\s*bank/i,
      /laxmi\s*sunrise\s*bank/i,
      /prabhu\s*bank/i,
      /citizens\s*bank\s*international/i,
      /sanima\s*bank/i,
      /nmb\s*bank/i,
      /prime\s*commercial\s*bank/i,
      /\besewa\b/i,
      /\bkhalti\b/i,
      /\bime\s*pay\b/i,
      /\bprabhu\s*pay\b/i,
      /\bcell\s*pay\b/i,
      /\bq\s*pay\b/i,
      /\bipay\b/i,
      /\bmo\s*ru\b/i,
      /\bhamro\s*pay\b/i,
      /\bcity\s*pay\b/i,
      /\bcips\b/i,
      /connect\s*ips/i,
    ],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// 4. URL EXTRACTION & PHISHING CHECK
// ─────────────────────────────────────────────────────────────────────────────

const SUSPICIOUS_TLD_RE = /\.(tk|ml|ga|cf|gq|xyz|top|pw|cc|su|ru|cn)$/i;

const DOMAIN_HOMOGLYPHS: Record<string, string> = {
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  ı: 'i',
  ο: 'o',
};
const DOMAIN_HOMOGLYPH_RE = new RegExp(`[${Object.keys(DOMAIN_HOMOGLYPHS).join('')}]`, 'g');

const KNOWN_DOMAINS: string[] = [
  'paypal.com',
  'amazon.com',
  'google.com',
  'facebook.com',
  'apple.com',
  'microsoft.com',
  'netflix.com',
  'instagram.com',
  'esewa.com.np',
  'khalti.com',
  'ime.com.np',
  'imepay.com.np',
  'fonepay.com',
  'connectips.com',
  'nchl.com.np',
  'bankofamerica.com',
  'chase.com',
  'wellsfargo.com',
  'citibank.com',
  'hsbc.com',
  'barclays.co.uk',
  'lloydsbank.com',
  'natwest.com',
  'santander.com',
  'deutschebank.com',
  'nabilbank.com',
  'globalimebank.com',
  'nicasiabank.com',
  'himalayanbank.com',
  'everestbankltd.com',
  'prabhubank.com',
  'nmb.com.np',
  'citizensbank.com.np',
  'sanima.com',
  'stripe.com',
  'square.com',
  'razorpay.com',
  'paytm.com',
  'phonepe.com',
  'googlepay.com',
  'gmail.com',
  'outlook.com',
  'yahoo.com',
  'hotmail.com',
  'twitter.com',
  'tiktok.com',
  'youtube.com',
  'linkedin.com',
  'snapchat.com',
  'whatsapp.com',
  'nepalitelecom.com.np',
  'ncell.com.np',
  'ird.gov.np',
  'moha.gov.np',
  'moe.gov.np',
];

/**
 * Known 18+ / adult-content domains. Matches the bare registrable domain
 * (and any subdomain of it) extracted from the submitted URL. Intentionally
 * conservative — major, unambiguous adult platforms only.
 */
const KNOWN_ADULT_DOMAINS: string[] = [
  'pornhub.com',
  'xvideos.com',
  'xnxx.com',
  'xhamster.com',
  'redtube.com',
  'youporn.com',
  'tube8.com',
  'spankbang.com',
  'onlyfans.com',
  'fansly.com',
  'brazzers.com',
  'chaturbate.com',
  'livejasmin.com',
  'stripchat.com',
  'motherless.com',
  'txxx.com',
  'porn.com',
  'beeg.com',
  'tnaflix.com',
  'camsoda.com',
  'myfreecams.com',
  'bongacams.com',
  'cam4.com',
  'manyvids.com',
  'rule34.xxx',
  'e-hentai.org',
  'hentaihaven.xxx',
  'fapdu.com',
  '4tube.com',
  'thumbzilla.com',
  'porntrex.com',
  'eporner.com',
  'pornone.com',
  'sex.com',
  'adultfriendfinder.com',
  'ashleymadison.com',
];

/** Known online gambling / betting / casino domains. */
const KNOWN_GAMBLING_DOMAINS: string[] = [
  'bet365.com',
  'draftkings.com',
  'fanduel.com',
  'pokerstars.com',
  '888casino.com',
  '888poker.com',
  'betway.com',
  'williamhill.com',
  'unibet.com',
  'stake.com',
  '1xbet.com',
  'ladbrokes.com',
  'betfair.com',
  'partypoker.com',
  'bovada.lv',
  'betmgm.com',
  'caesars.com',
  'skybet.com',
  'paddypower.com',
  'casumo.com',
  'leovegas.com',
  'melbet.com',
  'parimatch.com',
  'betwinner.com',
  '22bet.com',
  'dafabet.com',
  'betrivers.com',
  'pointsbet.com',
  'roobet.com',
  'gg.bet',
  'rajabets.com',
  '10cric.com',
  'lottoland.com',
  'jeetwin.com',
  'satta-king-fast.com',
  'lotus365.in',
];

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length,
    n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1]![j - 1]!
          : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[m]![n]!;
}

const URL_CANDIDATE_RE =
  /(https?:\/\/)?((?:[a-z0-9Ѐ-ӿ](?:[a-z0-9Ѐ-ӿ-]*[a-z0-9Ѐ-ӿ])?\.)+[a-z]{2,10})(\/[^\s<>"']*)?/gi;

/**
 * Hosts that never count as a risky external link.
 * Match is host === entry OR host ends with "." + entry, so subdomains inherit.
 */
const ALLOWED_HOSTS = [
  'google.com',
  'forms.gle',
  'goo.gle',
  'youtube.com',
  'youtu.be',
  'zoom.us',
  'teams.microsoft.com',
  'teams.live.com',
  'webex.com',
  'gov.np',
  'edu.np',
];

/** Google-owned hosts that serve user-uploaded pages — a standard phishing vector. */
const ALLOWLIST_EXCEPTIONS = [
  'sites.google.com',
  'script.google.com',
  'storage.googleapis.com',
  'firebasestorage.googleapis.com',
  'appspot.com',
  'web.app',
  'page.link',
];

/** Link shorteners: destination is hidden, so chaining one is a soft phishing signal. */
const SHORTENERS = new Set([
  't.co',
  'bit.ly',
  'bitly.com',
  'j.mp',
  'tinyurl.com',
  'goo.gl',
  'ow.ly',
  'buff.ly',
  'is.gd',
  'v.gd',
  'cutt.ly',
  'rb.gy',
  'rebrand.ly',
  'shorturl.at',
  's.id',
  'gg.gg',
  'tiny.cc',
  'short.gy',
  'bl.ink',
  'lnkd.in',
  't.ly',
  't.me',
  'wa.me',
  'clck.ru',
  'vk.cc',
  'adf.ly',
  'shrtco.de',
  'urlz.fr',
  'kutt.it',
  'po.st',
  'tr.im',
  'x.co',
  'u.to',
  'linktr.ee',
]);

/** TLDs accepted on a bare host (no scheme, no path). */
const BARE_HOST_TLDS = new Set([
  'com',
  'net',
  'org',
  'np',
  'info',
  'biz',
  'io',
  'co',
  'me',
  'app',
  'link',
  'xyz',
  'top',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'icu',
  'buzz',
  'click',
  'live',
  'online',
  'site',
  'shop',
  'vip',
  'win',
  'pw',
  'cc',
  'su',
  'ru',
  'cn',
  'in',
]);

/** Undoes common link obfuscation: hxxp://, khalti[dot]com, "khalti dot com". */
function deobfuscateLinks(text: string): string {
  return text
    .replace(/h(?:xx|\*\*)p(s?)\s*:\/\//gi, 'http$1://')
    .replace(/\s*[[({<]\s*(?:dot|\.)\s*[\])}>]\s*/gi, '.')
    .replace(/\s+dot\s+/gi, '.');
}

function isAllowedHost(host: string): boolean {
  const match = (list: string[]) => list.some((e) => host === e || host.endsWith(`.${e}`));
  return match(ALLOWED_HOSTS) && !match(ALLOWLIST_EXCEPTIONS);
}

/**
 * Extracts every link (scheme optional) and classifies each host as
 * allowlisted / shortener / suspicious-TLD / lookalike of a known domain.
 *
 * Only a `domain_spoof:*` match (typosquat of a real, known brand) marks the
 * result `flagged` — hard phishing evidence. A suspicious TLD or a plain
 * link shortener alone stays informational (`links[].reason` is still set,
 * used by the phishing signal combiner below) since both are too common on
 * legitimate sites to reject a URL over by themselves.
 */
function checkURLs(text: string): URLCheckResult {
  const cleaned = deobfuscateLinks(text);
  const links: URLLink[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  URL_CANDIDATE_RE.lastIndex = 0;
  while ((m = URL_CANDIDATE_RE.exec(cleaned)) !== null) {
    const [, scheme, rawHost, path] = m;
    const host = rawHost!
      .replace(DOMAIN_HOMOGLYPH_RE, (ch) => DOMAIN_HOMOGLYPHS[ch] ?? ch)
      .toLowerCase()
      .replace(/\.$/, '');
    const tld = host.slice(host.lastIndexOf('.') + 1);
    if (!scheme && !path && !BARE_HOST_TLDS.has(tld)) continue;
    if (seen.has(host)) continue;
    seen.add(host);

    const allowed = isAllowedHost(host);
    const registrable = host.replace(/^www\./, '');
    const shortener = SHORTENERS.has(registrable);

    let reason: string | null = null;
    if (!allowed) {
      if (shortener) reason = 'link_shortener';
      else if (SUSPICIOUS_TLD_RE.test(host)) reason = 'suspicious_tld';
      else {
        for (const known of KNOWN_DOMAINS) {
          const dist = levenshtein(registrable, known);
          if (dist > 0 && dist <= 2) {
            reason = `domain_spoof:${known}`;
            break;
          }
        }
      }
    }
    links.push({ host, allowed, shortener, reason });
  }

  const bad = links.find((l) => l.reason?.startsWith('domain_spoof:'));
  return {
    flagged: !!bad,
    reason: bad?.reason ?? null,
    domains: links.map((l) => l.host),
    links,
    hasUnknownLink: links.some((l) => !l.allowed),
    hasShortener: links.some((l) => l.shortener && !l.allowed),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4a. ADULT / GAMBLING DOMAIN CHECK
// ─────────────────────────────────────────────────────────────────────────────

interface DomainCategoryResult {
  adultDomains: string[];
  gamblingDomains: string[];
}

function checkDomainCategories(links: URLLink[]): DomainCategoryResult {
  const adultDomains: string[] = [];
  const gamblingDomains: string[] = [];

  for (const link of links) {
    const bareDomain = link.host.replace(/^www\./, '');

    if (
      KNOWN_ADULT_DOMAINS.some((d) => bareDomain === d || bareDomain.endsWith(`.${d}`)) &&
      !adultDomains.includes(bareDomain)
    ) {
      adultDomains.push(bareDomain);
    }
    if (
      KNOWN_GAMBLING_DOMAINS.some((d) => bareDomain === d || bareDomain.endsWith(`.${d}`)) &&
      !gamblingDomains.includes(bareDomain)
    ) {
      gamblingDomains.push(bareDomain);
    }
  }

  return { adultDomains, gamblingDomains };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4b. FINANCIAL BRAND DETECTION (spoof-aware)
// ─────────────────────────────────────────────────────────────────────────────

/** Nepali wallets, PSPs, banks and telcos — the brands phishers impersonate. */
const FINANCIAL_BRANDS = [
  'esewa',
  'khalti',
  'imepay',
  'fonepay',
  'connectips',
  'prabhupay',
  'cellpay',
  'namastepay',
  'moco',
  'qpay',
  'ipay',
  'citypay',
  'hamropay',
  'smartchoice',
  'muncha',
  'thaili',
  'sctpay',
  'fewapay',
  'khaltipay',
  'esewapay',
  'nabilbank',
  'nabil',
  'globalime',
  'nicasia',
  'prabhubank',
  'sanima',
  'nmbbank',
  'kumaribank',
  'laxmibank',
  'sunrisebank',
  'siddharthabank',
  'machhapuchchhre',
  'everestbank',
  'himalayanbank',
  'citizensbank',
  'rastriyabanijya',
  'nepalbank',
  'megabank',
  'civilbank',
  'muktinath',
  'garima',
  'shineresunga',
  'standardchartered',
  'nepalsbi',
  'primebank',
  'imeremit',
  'westernunion',
  'moneygram',
  'ncell',
  'nepaltelecom',
];

const BRAND_DEVANAGARI = [
  'खल्ती',
  'इसेवा',
  'ईसेवा',
  'आइएमई',
  'आईएमई',
  'फोनपे',
  'कनेक्ट आईपीएस',
  'नबिल',
  'ग्लोबल आईएमई',
  'प्रभु बैंक',
  'सानिमा',
  'कुमारी बैंक',
];

/** Generic money words — weaker signal than a named brand. */
const FINANCIAL_WORD_RE =
  /\b(bank|wallet|account|debit|credit\s*card|balance|transaction|kyc)\b|बैंक|खाता|वालेट|कारोबार/i;

/**
 * Folds a token to a spoof-resistant skeleton: confusable characters collapse
 * (l/1/i/! → i, 0 → o, rn → m …) and repeats are squeezed, so "KhaIti",
 * "khaltii" and "kha1ti" all fold to the same key as "khalti".
 */
function foldBrand(s: string): string {
  return s
    .normalize('NFC')
    .toLowerCase()
    .replace(/[^ऀ-ॿa-z0-9]+/g, '')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[l1|!ıíì]/g, 'i')
    .replace(/0/g, 'o')
    .replace(/3/g, 'e')
    .replace(/[4@]/g, 'a')
    .replace(/[5$]/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/9/g, 'g')
    .replace(/(.)\1+/g, '$1');
}

const BRAND_INDEX = new Map(FINANCIAL_BRANDS.map((b) => [foldBrand(b), b]));

/**
 * Finds a financial brand in the text, tolerating homoglyph/leet spoofing and
 * one typo. spoofed = the text did not spell the brand correctly.
 */
function detectBrand(content: string): BrandHit | null {
  for (const b of BRAND_DEVANAGARI) {
    if (content.includes(b)) return { brand: b, spoofed: false, as: b };
  }

  const tokens = content.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  let fuzzy: BrandHit | null = null;
  for (let i = 0; i < tokens.length; i++) {
    for (const cand of [tokens[i]!, tokens[i]! + (tokens[i + 1] ?? '')]) {
      const folded = foldBrand(cand);
      if (folded.length < 4) continue;

      const exact = BRAND_INDEX.get(folded);
      if (exact) {
        const raw = cand.toLowerCase().replace(/[^a-z0-9]/g, '');
        return { brand: exact, spoofed: raw !== exact, as: cand };
      }
      if (fuzzy || folded.length < 6) continue;
      for (const [key, brand] of BRAND_INDEX) {
        if (key[0] !== folded[0] || Math.abs(key.length - folded.length) > 1) continue;
        if (levenshtein(folded, key) === 1) {
          fuzzy = { brand, spoofed: !folded.startsWith(key), as: cand };
          break;
        }
      }
    }
  }
  return fuzzy;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4c. PHISHING SIGNAL COMBINER
// ─────────────────────────────────────────────────────────────────────────────

/** Individually weak signals that are damning in combination. */
const PHISH_SIGNALS: Record<string, RegExp[]> = {
  urgency: [
    /\b(suspend|block|deactivat|terminat|expir|freez|lock|restrict|disabl)(e|ed|es|ing|ion)?\b/i,
    /\b(with?in|in)\s+\d+\s*(hour|hr|minute|min|day)s?\b/i,
    /\b(immediately|urgent(ly)?|right\s+now|last\s+(warning|chance)|final\s+(notice|warning)|failure\s+to|or\s+else)\b/i,
    /निलम्बन|बन्द\s*हुने|रद्द\s*हुने|तुरुन्त|अन्तिम\s*(चेतावनी|मौका)/,
  ],
  action: [
    /\b(verify|verification|confirm|re[\W_]*activat\w*|update|re[\W_]*submit|validate|authenticate|kyc|unlock|restore|log\s?in|sign\s?in|click|tap|open\s+(the\s+)?link|claim)\b/i,
    /प्रमाणित|पुष्टि|अपडेट|क्लिक|लगइन|नवीकरण/,
  ],
  credential: [
    /\b(m?pin|otp|password|passcode|cvv|card\s*(number|details)|account\s*(number|details)|username|credentials?)\b/i,
    /पासवर्ड|पिन\s*नम्बर|ओटिपी|कार्ड\s*नम्बर|खाता\s*नम्बर|गोप्य\s*नम्बर/,
  ],
  reward: [
    /\b(cashback|bonus|reward|prize|winner|won|lucky\s+draw|free\s+(recharge|balance|data|cash)|refund|gift\s*(card|voucher))\b/i,
    /पुरस्कार|क्यासब्याक|बोनस|निःशुल्क|रिफन्ड|उपहार|भाग्यशाली/,
  ],
};

/** Scores the phishing/spam *shape* of the alias+URL from combined signals. */
function scorePhishing(content: string, urlResult: URLCheckResult): PhishingScore {
  const fired = new Set<string>();
  for (const [name, patterns] of Object.entries(PHISH_SIGNALS)) {
    if (patterns.some((p) => p.test(content))) fired.add(name);
  }

  const brandHit = detectBrand(content);
  const brand = !!brandHit;
  const spoofedBrand = !!brandHit?.spoofed;
  const money = brand || FINANCIAL_WORD_RE.test(content);
  // NOTE: `hasUnknownLink` is true for almost every legitimate submission in
  // this product — the allowlist is just Google/YouTube/Zoom/gov.np/edu.np,
  // and the whole point of a URL shortener is to accept arbitrary external
  // URLs. Unlike the original SMS filter (where "the message contains a
  // link" was informative), it carries no signal here, so it must never be
  // the thing that turns a single weak word match into a "combination".
  // What's left below only fires on real co-occurring evidence.
  const shortener = urlResult.hasShortener;
  const urgency = fired.has('urgency');
  const action = fired.has('action');
  const credential = fired.has('credential');
  const reward = fired.has('reward');

  const triggers: string[] = [];
  let score = 0;
  const add = (s: number, why: string) => {
    if (s > score) {
      score = s;
      triggers.push(why);
    }
  };

  if (spoofedBrand) add(0.95, `phish:spoofed_brand:${brandHit.brand}`);
  if (brand && (urgency || action || credential)) add(0.95, 'phish:brand_link_lure');
  if (credential && (urgency || action || brand)) add(0.92, 'phish:credential_request_with_lure');
  if (money && urgency && action) add(0.88, 'phish:money_urgency_action');
  if (shortener && (urgency || credential || brand)) add(0.85, 'phish:shortener_with_lure');
  if (reward && credential) add(0.85, 'phish:reward_bait_for_credentials');

  if (money && (urgency || credential)) add(0.5, 'phish:money_pressure');
  if (shortener) add(0.45, 'spam:link_shortener');

  const weak = [money, urgency, action, credential, reward].filter(Boolean).length;
  if (weak >= 3) add(0.45, 'phish:multi_signal');

  if (brand && score > 0) {
    triggers.push(`brand:${brandHit.brand}${spoofedBrand ? `(spelt "${brandHit.as}")` : ''}`);
  }
  return { score, triggers, brandHit };
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. RATE LIMITING (per requester IP)
// ─────────────────────────────────────────────────────────────────────────────

const rateBuckets = new Map<string, RateBucket>();
const RATE_WINDOW_MS = 60_000; // 1-minute sliding window
const RATE_MAX_CREATES = 20; // max shorten requests per identifier per window

function isRateLimited(identifier: string): boolean {
  const now = Date.now();
  let bucket = rateBuckets.get(identifier);
  if (!bucket || now - bucket.windowStart > RATE_WINDOW_MS) {
    bucket = { count: 0, windowStart: now };
    rateBuckets.set(identifier, bucket);
  }
  bucket.count++;

  if (Math.random() < 0.001) {
    for (const [id, b] of rateBuckets) {
      if (now - b.windowStart > RATE_WINDOW_MS * 2) rateBuckets.delete(id);
    }
  }

  return bucket.count > RATE_MAX_CREATES;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. CHEAP PRE-SCREEN
// ─────────────────────────────────────────────────────────────────────────────

const PRESCREEN_CHARS = new Set<string>('fscbdpwq!@$|0134567890');

function needsDeepScan(text: string): boolean {
  if (text.length > 500) return true;
  const lower = text.toLowerCase();
  for (const ch of lower) {
    if (PRESCREEN_CHARS.has(ch)) return true;
  }
  if (/[ऀ-ॿ]/.test(text)) return true;
  if (/https?:\/\//i.test(text) || /[a-z0-9-]\.[a-z]{2,10}(\/|\b)/i.test(text)) return true;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. CORE CHECK ENGINE
// ─────────────────────────────────────────────────────────────────────────────

function _pass(): CheckResult {
  return { decision: 'PASS', ruleId: null, category: null, matchedOn: null, riskScore: 0, triggers: [], meta: {} };
}

/**
 * Core content check. No side effects (pure function). `content` should be
 * `${alias ?? ''} ${url}` — the alias/title text and the destination URL
 * checked together in one pass.
 */
export function checkContent(content: string): CheckResult {
  if (!content || typeof content !== 'string') return _pass();

  const norm = normalise(content);
  const normWord = normaliseWords(content);
  const normTrie = normaliseForTrie(content);

  const triggers: string[] = [];
  let riskScore = 0;
  // Highest-scoring signal whose category is block-eligible — this (not the
  // overall max) is what actually decides BLOCK vs PASS and what the
  // rejection response describes.
  let topBlockRule: TopRule | null = null;
  // Highest-scoring signal overall, any category — kept for audit logging.
  let topRule: TopRule | null = null;

  const consider = (id: string, category: CategoryKey, matchedOn: MatchedOn, score: number) => {
    riskScore = Math.max(riskScore, score);
    if (!topRule || score > topRule.score) topRule = { id, category, matchedOn, score };
    if (BLOCK_CATEGORIES.has(category) && (!topBlockRule || score > topBlockRule.score)) {
      topBlockRule = { id, category, matchedOn, score };
    }
  };

  if (!needsDeepScan(content)) return _pass();

  // ── Trie scan (Aho-Corasick) with word boundary checking ────────────────
  const allTrieHits = BLOCKLIST_TRIE.search(normTrie);
  const trieHits = allTrieHits.filter((hit) => {
    const startIdx = hit.index;
    const endIdx = hit.index + hit.word.length;
    const isStartBoundary = startIdx === 0 || /\s/.test(normTrie[startIdx - 1]!);
    const isEndBoundary = endIdx === normTrie.length || /\s/.test(normTrie[endIdx]!);
    return isStartBoundary && isEndBoundary;
  });
  if (trieHits.length > 0) {
    const trieScore = Math.min(0.85 * trieHits.length, 0.95);
    triggers.push(`trie:${trieHits.map((h) => h.word).join(',')}`);
    consider('blocklist_trie', 'profanity', 'trie', trieScore);
  }

  // ── Regex rule battery (level-3 first) ─────────────────────────────────
  const sortedRules = [...RULES].sort((a, b) => b.level - a.level);
  const usesDigits = (p: RegExp): boolean => p.source.includes('\\d') || /[0-9]{3}/.test(p.source);

  for (const rule of sortedRules) {
    for (const pattern of rule.patterns) {
      const digitPattern = usesDigits(pattern);
      const hit: MatchedOn = pattern.test(content)
        ? 'original'
        : !digitPattern && pattern.test(norm)
          ? 'normalised'
          : !digitPattern && pattern.test(normWord)
            ? 'normalised-words'
            : null;

      if (hit) {
        const weight = CATEGORY_WEIGHTS[rule.category] ?? 0.5;
        const contrib = rule.confidence * weight;
        triggers.push(rule.id);
        consider(rule.id, rule.category, hit, contrib);
        break;
      }
    }
  }

  // ── URL / phishing check ────────────────────────────────────────────────
  const urlResult = checkURLs(content);
  let urlMeta: Record<string, unknown> = {};
  if (urlResult.flagged) {
    triggers.push(`url:${urlResult.reason}`);
    urlMeta = { phishingReason: urlResult.reason, domains: urlResult.domains };
    consider('phishing_url', 'phishing_url', 'url', CATEGORY_WEIGHTS.phishing_url);
  }

  // ── Phishing signal combiner (brand + urgency + action + link) ──────────
  const phish = scorePhishing(content, urlResult);
  if (phish.score > 0) {
    triggers.push(...phish.triggers);
    urlMeta = {
      ...urlMeta,
      domains: urlResult.domains,
      brand: phish.brandHit?.brand ?? null,
      brandSpoofed: phish.brandHit?.spoofed ?? false,
    };
    consider(
      phish.score >= THRESHOLD_BLOCK ? 'phishing_composite' : 'suspicious_composite',
      'scam_or_fraud',
      'signals',
      phish.score,
    );
  }

  // ── 18+ / gambling domain check ──────────────────────────────────────────
  // Direct known-domain matches carry effectively no false-positive risk, so
  // both categories can cross the block threshold outright.
  const domainCategoryResult = checkDomainCategories(urlResult.links);

  if (domainCategoryResult.adultDomains.length > 0) {
    triggers.push(`adult_domain:${domainCategoryResult.adultDomains.join(',')}`);
    urlMeta = { ...urlMeta, adultDomains: domainCategoryResult.adultDomains };
    consider('adult_domain_blocklist', 'adult_content', 'url', 0.9);
  }

  if (domainCategoryResult.gamblingDomains.length > 0) {
    triggers.push(`gambling_domain:${domainCategoryResult.gamblingDomains.join(',')}`);
    urlMeta = { ...urlMeta, gamblingDomains: domainCategoryResult.gamblingDomains };
    consider('gambling_domain_blocklist', 'gambling', 'url', 0.75);
  }

  // ── Decision ──────────────────────────────────────────────────────────
  const block = topBlockRule as TopRule | null;
  if (!block || block.score < THRESHOLD_BLOCK) return _pass();

  return {
    decision: 'BLOCK',
    ruleId: block.id,
    category: block.category,
    matchedOn: block.matchedOn,
    riskScore: Math.round(riskScore * 1000) / 1000,
    triggers,
    meta: { ...urlMeta },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. RESPONSE BUILDER
// ─────────────────────────────────────────────────────────────────────────────

const MESSAGES = {
  BLOCK: {
    en: 'This link could not be shortened because it violates our content policy (spam, phishing, adult content, gambling, or abusive text). Please try a different URL.',
    ne: 'यो लिंकलाई छोटो बनाउन सकिएन किनभने यसले हाम्रो सामग्री नीति उल्लङ्घन गर्छ (स्प्याम, फिसिङ, वयस्क सामग्री, जुवा, वा अपमानजनक शब्द)। कृपया फरक URL प्रयोग गर्नुहोस्।',
  },
} as const;

export function buildRejectionResponse(
  category: string | null,
  ruleId: string | null,
  riskScore: number | null,
): ContentPolicyResponse {
  return {
    error: `${MESSAGES.BLOCK.en} / ${MESSAGES.BLOCK.ne}`,
    code: 'CONTENT_POLICY_VIOLATION',
    category: category ?? null,
    ruleId: ruleId ?? null,
    riskScore: riskScore ?? null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. AUDIT LOG BUILDER
// ─────────────────────────────────────────────────────────────────────────────

export function buildAuditEntry(identifier: string, content: string, result: CheckResult): AuditEntry {
  return {
    ts: new Date().toISOString(),
    identifier,
    decision: result.decision,
    riskScore: result.riskScore,
    ruleId: result.ruleId,
    category: result.category,
    matchedOn: result.matchedOn,
    triggers: result.triggers,
    meta: result.meta,
    contentLen: content.length,
    excerpt: content.slice(0, 200),
  };
}

export function logContentFilterDecision(audit: AuditEntry, ctx: ContentFilterLogContext): void {
  if (audit.decision === 'PASS') return;

  const payload = {
    event: 'CONTENT_BLOCKED',
    request: {
      ip: ctx.ip ?? 'unknown',
      ...(ctx.userAgent && { userAgent: ctx.userAgent }),
      ...(ctx.endpoint && { endpoint: ctx.endpoint }),
    },
    filter: {
      decision: audit.decision,
      riskScore: audit.riskScore,
      ruleId: audit.ruleId,
      category: audit.category,
      matchedOn: audit.matchedOn,
      triggers: audit.triggers,
      meta: audit.meta,
    },
    content: { length: audit.contentLen, excerpt: audit.excerpt },
  };

  contentFilterLogger.info('CONTENT_BLOCKED', payload);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. FULL PIPELINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Runs a shorten-request's alias+URL through the filter and applies the
 * per-IP rate limit. Only a PASS with no rate-limit hit lets the caller
 * proceed to create the short link.
 */
export function filterUrlSubmission(content: string, opts: FilterOptions = {}): FilterResult {
  const identifier = opts.identifier ?? 'unknown';

  let result = checkContent(content);

  if (result.decision !== 'BLOCK' && isRateLimited(identifier)) {
    result = {
      decision: 'BLOCK',
      ruleId: 'rate_limit_exceeded',
      category: 'spam_duplicate',
      matchedOn: 'spam',
      riskScore: 0.8,
      triggers: [...result.triggers, 'rate_limit'],
      meta: result.meta,
    };
  }

  const response = result.decision === 'BLOCK' ? buildRejectionResponse(result.category, result.ruleId, result.riskScore) : null;
  const audit = buildAuditEntry(identifier, content, result);

  return { result, response, audit };
}
