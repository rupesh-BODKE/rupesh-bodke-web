/* ================================================================
   FinanceTracker — app.js
   Complete client-side personal finance application.
   Data stored in localStorage; no server required.
   ================================================================ */
'use strict';

// ================================================================
// CONSTANTS
// ================================================================

const CATEGORIES = [
  { id: 'food',       name: 'Food & Dining',    icon: '🍕', type: 'expense' },
  { id: 'transport',  name: 'Transportation',   icon: '🚗', type: 'expense' },
  { id: 'shopping',   name: 'Shopping',         icon: '🛍️', type: 'expense' },
  { id: 'entertain',  name: 'Entertainment',    icon: '🎬', type: 'expense' },
  { id: 'health',     name: 'Health & Fitness', icon: '💊', type: 'expense' },
  { id: 'utilities',  name: 'Utilities',        icon: '💡', type: 'expense' },
  { id: 'housing',    name: 'Housing / Rent',   icon: '🏠', type: 'expense' },
  { id: 'education',  name: 'Education',        icon: '📚', type: 'expense' },
  { id: 'travel',     name: 'Travel',           icon: '✈️',  type: 'expense' },
  { id: 'personal',   name: 'Personal Care',    icon: '💅', type: 'expense' },
  { id: 'insurance',  name: 'Insurance',        icon: '🛡️', type: 'expense' },
  { id: 'salary',     name: 'Salary / Wages',   icon: '💼', type: 'income' },
  { id: 'freelance',  name: 'Freelance',        icon: '💻', type: 'income' },
  { id: 'investment', name: 'Investments',      icon: '📈', type: 'income' },
  { id: 'gift',       name: 'Gifts / Bonus',    icon: '🎁', type: 'income' },
  { id: 'other',      name: 'Other',            icon: '📦', type: 'both' },
];

const CURRENCIES = [
  { code: 'USD', symbol: '$',   name: 'US Dollar' },
  { code: 'EUR', symbol: '€',   name: 'Euro' },
  { code: 'GBP', symbol: '£',   name: 'British Pound' },
  { code: 'INR', symbol: '₹',   name: 'Indian Rupee' },
  { code: 'JPY', symbol: '¥',   name: 'Japanese Yen' },
  { code: 'CAD', symbol: 'C$',  name: 'Canadian Dollar' },
  { code: 'AUD', symbol: 'A$',  name: 'Australian Dollar' },
  { code: 'CHF', symbol: 'Fr',  name: 'Swiss Franc' },
  { code: 'CNY', symbol: '¥',   name: 'Chinese Yuan' },
  { code: 'BRL', symbol: 'R$',  name: 'Brazilian Real' },
  { code: 'MXN', symbol: '$',   name: 'Mexican Peso' },
  { code: 'SGD', symbol: 'S$',  name: 'Singapore Dollar' },
];

// Exchange rates relative to 1 USD
const DEFAULT_RATES = {
  USD: 1, EUR: 0.92, GBP: 0.79, INR: 83.12,
  JPY: 149.50, CAD: 1.36, AUD: 1.53, CHF: 0.88,
  CNY: 7.24, BRL: 4.97, MXN: 17.15, SGD: 1.34,
};

const CHART_COLORS = [
  '#38bdf8','#818cf8','#34d399','#f87171',
  '#fbbf24','#a78bfa','#fb7185','#4ade80',
  '#60a5fa','#f472b6','#a3e635','#fb923c',
];

const PER_PAGE   = 15;
const TOKEN_KEY  = 'ft_token';
const USERS_KEY  = 'ft_users';

// ================================================================
// SECURITY UTILITIES
// ================================================================

/**
 * Escape HTML to prevent XSS when inserting user content into innerHTML.
 */
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

// ================================================================
// CRYPTO UTILITIES
// ================================================================

const Crypto = {
  /**
   * Generate a random 128-bit hex salt (16 bytes).
   * A unique salt is stored per user to prevent rainbow-table attacks.
   */
  generateSalt() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Derive a key from the password using PBKDF2-SHA-256 (100 000 iterations).
   * This is deliberately slow to resist brute-force attacks, even when the
   * hashed value is obtained from localStorage.
   * @param {string} password  Plaintext password
   * @param {string} salt      Hex salt stored with the user record
   */
  async hashPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100_000, hash: 'SHA-256' },
      keyMaterial, 256,
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /** Generate a collision-resistant random ID */
  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
  },

  /**
   * Create a lightweight client-side session token.
   *
   * SECURITY NOTE: This token is stored in localStorage alongside all other
   * app data, so an attacker with access to localStorage can already read all
   * data directly.  The token is intentionally kept simple — its only purpose
   * is to persist the login session across page reloads within the same
   * browser origin.  Do NOT use this design in a networked/server context.
   */
  createToken(userId) {
    const payload = { userId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 };
    return btoa(JSON.stringify(payload));
  },

  parseToken(token) {
    try { return JSON.parse(atob(token)); } catch { return null; }
  },

  isTokenValid(token) {
    const p = this.parseToken(token);
    return p !== null && typeof p.exp === 'number' && p.exp > Date.now();
  },
};

// ================================================================
// STORAGE LAYER  (all data lives in localStorage)
// ================================================================

const Storage = {
  /* ── Users ─────────────────────────────────────── */
  getUsers()                { return JSON.parse(localStorage.getItem(USERS_KEY) || '[]'); },
  saveUsers(u)              { localStorage.setItem(USERS_KEY, JSON.stringify(u)); },
  getUserById(id)           { return this.getUsers().find(u => u.id === id) || null; },
  getUserByUsername(name)   {
    const n = name.toLowerCase();
    return this.getUsers().find(u => u.username.toLowerCase() === n) || null;
  },
  saveUser(user) {
    const users = this.getUsers();
    const idx   = users.findIndex(u => u.id === user.id);
    if (idx >= 0) users[idx] = user; else users.push(user);
    this.saveUsers(users);
  },

  /* ── Transactions ───────────────────────────────── */
  getTransactions(uid)     { return JSON.parse(localStorage.getItem(`ft_txn_${uid}`) || '[]'); },
  saveTransactions(uid, d) { localStorage.setItem(`ft_txn_${uid}`, JSON.stringify(d)); },
  addTransaction(uid, txn) {
    const list = this.getTransactions(uid);
    list.unshift(txn);
    this.saveTransactions(uid, list);
  },
  updateTransaction(uid, txn) {
    this.saveTransactions(uid, this.getTransactions(uid).map(t => t.id === txn.id ? txn : t));
  },
  deleteTransaction(uid, id) {
    this.saveTransactions(uid, this.getTransactions(uid).filter(t => t.id !== id));
  },

  /* ── Budgets ────────────────────────────────────── */
  getBudgets(uid)          { return JSON.parse(localStorage.getItem(`ft_bud_${uid}`) || '[]'); },
  saveBudgets(uid, d)      { localStorage.setItem(`ft_bud_${uid}`, JSON.stringify(d)); },

  /* ── Bills ──────────────────────────────────────── */
  getBills(uid)            { return JSON.parse(localStorage.getItem(`ft_bill_${uid}`) || '[]'); },
  saveBills(uid, d)        { localStorage.setItem(`ft_bill_${uid}`, JSON.stringify(d)); },

  /* ── Settings ───────────────────────────────────── */
  getSettings(uid) {
    const defaults = { currency: 'USD', rates: { ...DEFAULT_RATES } };
    const stored   = JSON.parse(localStorage.getItem(`ft_set_${uid}`) || '{}');
    return { ...defaults, ...stored, rates: { ...defaults.rates, ...(stored.rates || {}) } };
  },
  saveSettings(uid, d) { localStorage.setItem(`ft_set_${uid}`, JSON.stringify(d)); },

  /* ── Clear all user data ────────────────────────── */
  clearAllUserData(uid) {
    ['ft_txn_', 'ft_bud_', 'ft_bill_', 'ft_set_'].forEach(p =>
      localStorage.removeItem(`${p}${uid}`)
    );
  },

  /* ── Full export / import ───────────────────────── */
  exportAll(uid) {
    return {
      transactions: this.getTransactions(uid),
      budgets:      this.getBudgets(uid),
      bills:        this.getBills(uid),
      settings:     this.getSettings(uid),
    };
  },
  importAll(uid, data) {
    if (data.transactions) this.saveTransactions(uid, data.transactions);
    if (data.budgets)      this.saveBudgets(uid, data.budgets);
    if (data.bills)        this.saveBills(uid, data.bills);
    if (data.settings)     this.saveSettings(uid, data.settings);
  },
};

// ================================================================
// APPLICATION STATE
// ================================================================

const App = {
  user:        null,
  settings:    null,
  currentView: 'dashboard',
  txnPage:     1,
  txnFilters:  { search: '', type: '', category: '', month: '' },
  billsTab:    'upcoming',
  charts:      {},

  getTransactions()  { return Storage.getTransactions(this.user.id); },
  getBudgets()       { return Storage.getBudgets(this.user.id); },
  getBills()         { return Storage.getBills(this.user.id); },

  getCurrentMonth()  { return new Date().toISOString().slice(0, 7); },

  getCategoryById(id) {
    return CATEGORIES.find(c => c.id === id) || { name: id, icon: '📦' };
  },

  getCurrencySymbol(code) {
    return (CURRENCIES.find(c => c.code === code) || { symbol: code }).symbol;
  },

  /**
   * Format an amount with the user's default currency symbol.
   * `currency` parameter is optional; falls back to default.
   */
  formatCurrency(amount, currency) {
    const code = currency || this.settings.currency;
    const sym  = this.getCurrencySymbol(code);
    return `${sym}${Math.abs(amount).toLocaleString('en-US', {
      minimumFractionDigits: 2, maximumFractionDigits: 2,
    })}`;
  },

  /**
   * Convert an amount from `fromCurrency` to the user's default currency
   * using the stored exchange rates (all relative to USD as base).
   */
  convertToDefault(amount, fromCurrency) {
    const rates  = this.settings.rates;
    const target = this.settings.currency;
    if (fromCurrency === target) return amount;
    // source → USD → target
    const usd = amount / (rates[fromCurrency] || 1);
    return usd * (rates[target] || 1);
  },
};

// ================================================================
// AUTHENTICATION MODULE
// ================================================================

const Auth = {
  async init() {
    // Ensure demo account exists with PBKDF2-hashed password
    const existing = Storage.getUserByUsername('demo');
    if (!existing || !existing.passwordSalt) {
      // Create (or recreate) demo user with proper PBKDF2 password hashing
      if (existing) {
        const users = Storage.getUsers().filter(u => u.username !== 'demo');
        Storage.saveUsers(users);
      }
      await this._createDemoUser();
    }

    const token = localStorage.getItem(TOKEN_KEY);
    if (token && Crypto.isTokenValid(token)) {
      const payload = Crypto.parseToken(token);
      if (payload) {
        const user = Storage.getUserById(payload.userId);
        if (user) {
          App.user     = user;
          App.settings = Storage.getSettings(user.id);
          return true;
        }
      }
    }
    return false;
  },

  async _createDemoUser() {
    const salt = Crypto.generateSalt();
    const hash = await Crypto.hashPassword('demo123', salt);
    const user = {
      id: Crypto.generateId(), name: 'Demo User', username: 'demo',
      email: 'demo@financetracker.app', passwordHash: hash, passwordSalt: salt,
      createdAt: new Date().toISOString(),
    };
    Storage.saveUser(user);
    this._seedDemoData(user.id);
  },

  _seedDemoData(uid) {
    const today    = new Date();
    const txns     = [];
    const budgets  = [];
    const settings = { currency: 'USD', rates: { ...DEFAULT_RATES } };

    for (let m = 0; m < 3; m++) {
      const d     = new Date(today.getFullYear(), today.getMonth() - m, 1);
      const month = d.toISOString().slice(0, 7);

      txns.push({
        id: Crypto.generateId(), type: 'income', amount: 4500,
        currency: 'USD', amountDefault: 4500, category: 'salary',
        description: 'Monthly Salary', notes: '', date: `${month}-01`,
        createdAt: new Date(d).toISOString(),
      });

      const expenses = [
        { a: 850,   cat: 'housing',   desc: 'Rent',              day: 1  },
        { a: 120,   cat: 'utilities', desc: 'Electricity Bill',  day: 5  },
        { a: 45,    cat: 'utilities', desc: 'Internet',          day: 7  },
        { a: 280,   cat: 'food',      desc: 'Grocery Shopping',  day: 8  },
        { a: 65,    cat: 'transport', desc: 'Fuel',              day: 10 },
        { a: 15.99, cat: 'entertain', desc: 'Netflix',           day: 12 },
        { a: 45,    cat: 'food',      desc: 'Restaurant Dinner', day: 14 },
        { a: 89,    cat: 'health',    desc: 'Gym Membership',    day: 15 },
        { a: 120,   cat: 'shopping',  desc: 'Clothing',          day: 18 },
        { a: 35,    cat: 'food',      desc: 'Coffee & Snacks',   day: 20 },
        { a: 25,    cat: 'transport', desc: 'Taxi / Uber',       day: 22 },
      ];

      expenses.forEach(e => {
        const ds  = `${month}-${String(e.day).padStart(2, '0')}`;
        const dob = new Date(ds + 'T00:00:00');
        if (dob <= today) {
          txns.push({
            id: Crypto.generateId(), type: 'expense', amount: e.a,
            currency: 'USD', amountDefault: e.a, category: e.cat,
            description: e.desc, notes: '', date: ds,
            createdAt: dob.toISOString(),
          });
        }
      });

      if (m < 2) {
        [
          { cat: 'food',      a: 500 }, { cat: 'transport', a: 150 },
          { cat: 'housing',   a: 900 }, { cat: 'entertain',  a: 100 },
          { cat: 'health',    a: 120 }, { cat: 'utilities',  a: 200 },
          { cat: 'shopping',  a: 200 },
        ].forEach(b =>
          budgets.push({ id: Crypto.generateId(), category: b.cat, amount: b.a, month })
        );
      }
    }

    const billItems = [
      { name: 'Netflix',        amount: 15.99, dueDate: this._nextDue(15), recurring: 'monthly', category: 'entertain' },
      { name: 'Electricity',    amount: 120,   dueDate: this._nextDue(5),  recurring: 'monthly', category: 'utilities' },
      { name: 'Internet',       amount: 45,    dueDate: this._nextDue(7),  recurring: 'monthly', category: 'utilities' },
      { name: 'Gym Membership', amount: 89,    dueDate: this._nextDue(1),  recurring: 'monthly', category: 'health'    },
      { name: 'Car Insurance',  amount: 180,   dueDate: this._nextDue(20), recurring: 'monthly', category: 'insurance' },
    ];

    Storage.saveTransactions(uid, txns);
    Storage.saveBudgets(uid, budgets);
    Storage.saveBills(uid, billItems.map(b => ({
      id: Crypto.generateId(), ...b, currency: 'USD',
      paid: false, paidDate: null, notes: '', createdAt: new Date().toISOString(),
    })));
    Storage.saveSettings(uid, settings);
  },

  _nextDue(day) {
    const d = new Date();
    d.setDate(day);
    if (d <= new Date()) d.setMonth(d.getMonth() + 1);
    return d.toISOString().slice(0, 10);
  },

  async login(username, password) {
    const user = Storage.getUserByUsername(username);
    if (!user) throw new Error('Invalid username or password');
    // All users created since v2 have a passwordSalt for PBKDF2
    if (!user.passwordSalt) throw new Error('Account requires re-registration — please sign up again');
    const hash = await Crypto.hashPassword(password, user.passwordSalt);
    if (hash !== user.passwordHash) throw new Error('Invalid username or password');
    localStorage.setItem(TOKEN_KEY, Crypto.createToken(user.id));
    App.user     = user;
    App.settings = Storage.getSettings(user.id);
  },

  async register(name, username, email, password) {
    if (Storage.getUserByUsername(username)) throw new Error('Username already taken');
    const salt = Crypto.generateSalt();
    const user = {
      id: Crypto.generateId(), name, username, email,
      passwordHash: await Crypto.hashPassword(password, salt),
      passwordSalt: salt,
      createdAt: new Date().toISOString(),
    };
    Storage.saveUser(user);
    localStorage.setItem(TOKEN_KEY, Crypto.createToken(user.id));
    App.user     = user;
    App.settings = Storage.getSettings(user.id);
  },

  logout() {
    localStorage.removeItem(TOKEN_KEY);
    // Destroy chart instances to release canvas memory
    Object.values(App.charts).forEach(c => { try { c.destroy(); } catch (_) {} });
    App.user = null; App.settings = null; App.charts = {};
  },
};

// ================================================================
// UI UTILITIES
// ================================================================

const UI = {
  showToast(message, type = 'info', duration = 3200) {
    const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
    const el    = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${escapeHtml(message)}</span>`;
    document.getElementById('toast-container').appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .3s';
      el.style.opacity    = '0';
      setTimeout(() => el.remove(), 320);
    }, duration);
  },

  showModal(id) {
    document.getElementById(id).classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  },

  hideModal(id) {
    document.getElementById(id).classList.add('hidden');
    document.body.style.overflow = '';
  },

  showConfirm(title, message) {
    return new Promise(resolve => {
      document.getElementById('confirm-title').textContent   = title;
      document.getElementById('confirm-message').textContent = message;
      this.showModal('modal-confirm');
      const ok     = document.getElementById('confirm-ok');
      const cancel = document.getElementById('confirm-cancel');
      const done   = result => { this.hideModal('modal-confirm'); resolve(result); };
      ok.onclick     = () => done(true);
      cancel.onclick = () => done(false);
    });
  },

  showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    const viewEl = document.getElementById(`view-${viewId}`);
    if (viewEl) viewEl.classList.remove('hidden');
    document.querySelectorAll('.nav-item').forEach(n =>
      n.classList.toggle('active', n.dataset.view === viewId)
    );
    App.currentView = viewId;
    // Close sidebar on mobile
    document.getElementById('sidebar').classList.remove('open');
    const overlay = document.getElementById('sidebar-overlay');
    if (overlay) overlay.classList.remove('visible');
  },

  destroyChart(key) {
    if (App.charts[key]) {
      try { App.charts[key].destroy(); } catch (_) {}
      delete App.charts[key];
    }
  },

  formatDate(dateStr) {
    if (!dateStr) return '—';
    const [y, m, d] = dateStr.split('-').map(Number);
    return new Date(y, m - 1, d).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    });
  },

  daysUntil(dateStr) {
    const today  = new Date(); today.setHours(0, 0, 0, 0);
    const [y, m, d] = dateStr.split('-').map(Number);
    const target = new Date(y, m - 1, d);
    return Math.round((target - today) / 86400000);
  },

  /** Populate a <select> with currency options */
  populateCurrencySelect(selectId, selectedCode) {
    const sel = document.getElementById(selectId);
    if (!sel) return;
    sel.innerHTML = CURRENCIES.map(c =>
      `<option value="${escapeHtml(c.code)}" ${c.code === selectedCode ? 'selected' : ''}>${escapeHtml(c.code)} — ${escapeHtml(c.name)}</option>`
    ).join('');
  },

  /** Populate a <select> with category options */
  populateCategorySelect(selectId, typeFilter, selectedId) {
    const sel = document.getElementById(selectId);
    if (!sel) return;
    const cats = CATEGORIES.filter(c => !typeFilter || c.type === typeFilter || c.type === 'both');
    sel.innerHTML = cats.map(c =>
      `<option value="${c.id}" ${c.id === selectedId ? 'selected' : ''}>${c.icon} ${escapeHtml(c.name)}</option>`
    ).join('');
  },
};

// ================================================================
// DASHBOARD MODULE
// ================================================================

const Dashboard = {
  render() {
    const txns  = App.getTransactions();
    const bills = App.getBills();
    const month = App.getCurrentMonth();

    const mTxns   = txns.filter(t => t.date.startsWith(month));
    const income  = mTxns.filter(t => t.type === 'income' ).reduce((s, t) => s + t.amountDefault, 0);
    const expense = mTxns.filter(t => t.type === 'expense').reduce((s, t) => s + t.amountDefault, 0);
    const balance = income - expense;
    const savingsRate = income > 0 ? ((balance / income) * 100).toFixed(1) : 0;

    document.getElementById('dash-income' ).textContent = App.formatCurrency(income);
    document.getElementById('dash-expense').textContent = App.formatCurrency(expense);
    document.getElementById('dash-balance').textContent = App.formatCurrency(Math.abs(balance));
    document.getElementById('dash-savings').textContent = `${savingsRate}%`;

    const balEl = document.getElementById('dash-balance');
    balEl.style.color = balance >= 0 ? 'var(--success)' : 'var(--danger)';
    if (balance < 0) balEl.textContent = `-${App.formatCurrency(Math.abs(balance))}`;

    this._renderCategoryChart(mTxns);
    this._renderCashflowChart(txns);
    this._renderRecentTransactions(txns.slice(0, 6));
    this._renderUpcomingBills(bills);

    // Overdue badge on sidebar Bills link
    const overdue = bills.filter(b => !b.paid && UI.daysUntil(b.dueDate) < 0).length;
    const badge   = document.getElementById('bills-badge');
    badge.textContent = overdue;
    badge.classList.toggle('hidden', overdue === 0);
  },

  _renderCategoryChart(txns) {
    if (typeof Chart === 'undefined') return;
    UI.destroyChart('dashCat');
    const canvas = document.getElementById('chart-category');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const expenses = txns.filter(t => t.type === 'expense');
    if (!expenses.length) { ctx.clearRect(0, 0, canvas.width, canvas.height); return; }

    const byCategory = {};
    expenses.forEach(t => { byCategory[t.category] = (byCategory[t.category] || 0) + t.amountDefault; });
    const sorted = Object.entries(byCategory).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const labels = sorted.map(([id]) => App.getCategoryById(id).name);
    const data   = sorted.map(([, v]) => v);
    const total  = data.reduce((a, b) => a + b, 0);

    App.charts.dashCat = new Chart(ctx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: CHART_COLORS, borderWidth: 0, hoverOffset: 6 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12, padding: 10 },
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${App.formatCurrency(ctx.raw)}  (${total > 0 ? (ctx.raw / total * 100).toFixed(1) : 0}%)`,
            },
          },
        },
      },
    });
  },

  _renderCashflowChart(txns) {
    if (typeof Chart === 'undefined') return;
    UI.destroyChart('dashFlow');
    const ctx = document.getElementById('chart-cashflow');
    if (!ctx) return;

    const months = Array.from({ length: 6 }, (_, i) => {
      const d = new Date(); d.setDate(1); d.setMonth(d.getMonth() - (5 - i));
      return d.toISOString().slice(0, 7);
    });

    const labels      = months.map(m => { const [y, mo] = m.split('-'); return new Date(+y, +mo - 1).toLocaleDateString('en-US', { month: 'short', year: '2-digit' }); });
    const incomeData  = months.map(m => txns.filter(t => t.type === 'income'  && t.date.startsWith(m)).reduce((s, t) => s + t.amountDefault, 0));
    const expenseData = months.map(m => txns.filter(t => t.type === 'expense' && t.date.startsWith(m)).reduce((s, t) => s + t.amountDefault, 0));

    App.charts.dashFlow = new Chart(ctx.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'Income',   data: incomeData,  backgroundColor: 'rgba(52,211,153,.7)',  borderRadius: 5 },
          { label: 'Expenses', data: expenseData, backgroundColor: 'rgba(248,113,113,.7)', borderRadius: 5 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(51,65,85,.4)' } },
          y: { ticks: { color: '#94a3b8', callback: v => App.formatCurrency(v) }, grid: { color: 'rgba(51,65,85,.4)' } },
        },
      },
    });
  },

  _renderRecentTransactions(txns) {
    const el = document.getElementById('recent-transactions');
    if (!txns.length) {
      el.innerHTML = '<p class="empty-state">No transactions yet. Click "+ Add Transaction" to get started!</p>';
      return;
    }
    el.innerHTML = txns.map(t => {
      const cat  = App.getCategoryById(t.category);
      const sign = t.type === 'income' ? '+' : '-';
      return `
        <div class="recent-txn-item">
          <div class="txn-icon">${cat.icon}</div>
          <div style="flex:1;min-width:0">
            <div class="txn-desc">${escapeHtml(t.description)}</div>
            <div class="txn-cat">${escapeHtml(cat.name)}</div>
          </div>
          <div class="txn-date">${UI.formatDate(t.date)}</div>
          <div class="txn-amt ${t.type === 'income' ? 'amount-income' : 'amount-expense'}">
            ${sign}${App.formatCurrency(t.amountDefault)}
          </div>
        </div>`;
    }).join('');
  },

  _renderUpcomingBills(bills) {
    const el       = document.getElementById('upcoming-bills');
    const upcoming = bills
      .filter(b => !b.paid && UI.daysUntil(b.dueDate) <= 30)
      .sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate))
      .slice(0, 5);

    if (!upcoming.length) {
      el.innerHTML = '<p class="empty-state">No upcoming bills in the next 30 days.</p>';
      return;
    }
    el.innerHTML = upcoming.map(b => {
      const days      = UI.daysUntil(b.dueDate);
      const dotClass  = days < 0 ? 'overdue' : days <= 7 ? 'due-soon' : 'upcoming';
      const metaClass = days < 0 ? 'bill-overdue' : days <= 7 ? 'bill-due-soon' : '';
      const statusTxt = days < 0 ? `${Math.abs(days)}d overdue` : days === 0 ? 'Due today!' : `Due in ${days}d`;
      return `
        <div class="bill-item">
          <div class="bill-status-dot ${dotClass}"></div>
          <div class="bill-info">
            <div class="bill-name">${escapeHtml(b.name)}</div>
            <div class="bill-meta ${metaClass}">${statusTxt}</div>
          </div>
          <div class="bill-amount">${App.formatCurrency(App.convertToDefault(b.amount, b.currency))}</div>
        </div>`;
    }).join('');
  },
};

// ================================================================
// TRANSACTIONS MODULE
// ================================================================

const Transactions = {
  _getFiltered() {
    let list = App.getTransactions();
    const { search, type, category, month } = App.txnFilters;
    if (search)   {
      const q = search.toLowerCase();
      list = list.filter(t =>
        t.description.toLowerCase().includes(q) ||
        (t.notes || '').toLowerCase().includes(q)
      );
    }
    if (type)     list = list.filter(t => t.type === type);
    if (category) list = list.filter(t => t.category === category);
    if (month)    list = list.filter(t => t.date.startsWith(month));
    return list.sort((a, b) => new Date(b.date) - new Date(a.date) || b.createdAt.localeCompare(a.createdAt));
  },

  render() {
    const all   = this._getFiltered();
    const total = all.length;
    const pages = Math.max(1, Math.ceil(total / PER_PAGE));
    App.txnPage = Math.min(App.txnPage, pages);
    const slice = all.slice((App.txnPage - 1) * PER_PAGE, App.txnPage * PER_PAGE);

    const tbody = document.getElementById('transactions-table-body');
    if (!slice.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No transactions found</td></tr>';
    } else {
      tbody.innerHTML = slice.map(t => {
        const cat  = App.getCategoryById(t.category);
        const sign = t.type === 'income' ? '+' : '-';
        const originalNote = (t.currency !== App.settings.currency)
          ? `<div style="font-size:.73rem;color:var(--muted)">${escapeHtml(t.currency)} ${Number(t.amount).toFixed(2)}</div>`
          : '';
        return `
          <tr>
            <td>${UI.formatDate(t.date)}</td>
            <td>
              <div style="font-weight:500">${escapeHtml(t.description)}</div>
              ${t.notes ? `<div style="font-size:.78rem;color:var(--muted)">${escapeHtml(t.notes)}</div>` : ''}
            </td>
            <td>${escapeHtml(cat.icon)} ${escapeHtml(cat.name)}</td>
            <td><span class="badge badge-${t.type}">${t.type.charAt(0).toUpperCase() + t.type.slice(1)}</span></td>
            <td class="${t.type === 'income' ? 'amount-income' : 'amount-expense'}">
              ${sign}${App.formatCurrency(t.amountDefault)}${originalNote}
            </td>
            <td>
              <button class="btn-icon" data-action="edit-txn" data-id="${escapeHtml(t.id)}" title="Edit">✏️</button>
              <button class="btn-icon danger" data-action="del-txn" data-id="${escapeHtml(t.id)}" title="Delete">🗑️</button>
            </td>
          </tr>`;
      }).join('');
    }
    this._renderPagination(pages);
  },

  _renderPagination(pages) {
    const el = document.getElementById('txn-pagination');
    if (pages <= 1) { el.innerHTML = ''; return; }
    let html = `<button class="page-btn" data-page="${App.txnPage - 1}" ${App.txnPage === 1 ? 'disabled' : ''}>‹</button>`;
    for (let i = 1; i <= pages; i++) {
      if (pages > 7 && Math.abs(i - App.txnPage) > 2 && i !== 1 && i !== pages) {
        if (i === 2 || i === pages - 1) html += '<span style="color:var(--muted);padding:.4rem .2rem">…</span>';
        continue;
      }
      html += `<button class="page-btn ${i === App.txnPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
    }
    html += `<button class="page-btn" data-page="${App.txnPage + 1}" ${App.txnPage === pages ? 'disabled' : ''}>›</button>`;
    el.innerHTML = html;
  },

  goPage(page) { App.txnPage = page; this.render(); },

  openAdd() {
    document.getElementById('txn-id').value    = '';
    document.getElementById('txn-modal-title').textContent = 'Add Transaction';
    document.getElementById('transaction-form').reset();
    document.getElementById('txn-date').value  = new Date().toISOString().slice(0, 10);
    document.getElementById('txn-type').value  = 'expense';
    UI.populateCurrencySelect('txn-currency', App.settings.currency);
    UI.populateCategorySelect('txn-category', 'expense');
    UI.showModal('modal-transaction');
  },

  openEdit(id) {
    const t = App.getTransactions().find(tx => tx.id === id);
    if (!t) return;
    document.getElementById('txn-id').value    = t.id;
    document.getElementById('txn-modal-title').textContent = 'Edit Transaction';
    document.getElementById('txn-type').value  = t.type;
    document.getElementById('txn-date').value  = t.date;
    document.getElementById('txn-desc').value  = t.description;
    document.getElementById('txn-amount').value= t.amount;
    document.getElementById('txn-notes').value = t.notes || '';
    UI.populateCurrencySelect('txn-currency', t.currency);
    UI.populateCategorySelect('txn-category', t.type, t.category);
    document.getElementById('txn-currency').value  = t.currency;
    document.getElementById('txn-category').value  = t.category;
    UI.showModal('modal-transaction');
  },

  async confirmDelete(id) {
    const ok = await UI.showConfirm('Delete Transaction', 'Delete this transaction? This cannot be undone.');
    if (!ok) return;
    Storage.deleteTransaction(App.user.id, id);
    this.render();
    Dashboard.render();
    UI.showToast('Transaction deleted', 'success');
  },

  save(e) {
    e.preventDefault();
    const id       = document.getElementById('txn-id').value;
    const type     = document.getElementById('txn-type').value;
    const date     = document.getElementById('txn-date').value;
    const desc     = document.getElementById('txn-desc').value.trim();
    const amount   = parseFloat(document.getElementById('txn-amount').value);
    const currency = document.getElementById('txn-currency').value;
    const category = document.getElementById('txn-category').value;
    const notes    = document.getElementById('txn-notes').value.trim();

    const amountDefault = App.convertToDefault(amount, currency);
    const now = new Date().toISOString();

    if (id) {
      const existing = App.getTransactions().find(t => t.id === id);
      Storage.updateTransaction(App.user.id, {
        ...existing, type, date, description: desc, amount, currency, amountDefault, category, notes,
      });
      UI.showToast('Transaction updated', 'success');
    } else {
      Storage.addTransaction(App.user.id, {
        id: Crypto.generateId(), type, date, description: desc, amount, currency,
        amountDefault, category, notes, createdAt: now,
      });
      UI.showToast('Transaction added', 'success');
    }

    UI.hideModal('modal-transaction');
    this.render();
    Dashboard.render();
  },

  exportCSV() {
    const txns = this._getFiltered();
    if (!txns.length) { UI.showToast('No transactions to export', 'warning'); return; }

    const headers = ['Date', 'Description', 'Category', 'Type', 'Amount', 'Currency', `Amount (${App.settings.currency})`, 'Notes'];
    const rows    = txns.map(t => [
      t.date,
      `"${String(t.description).replace(/"/g, '""')}"`,
      App.getCategoryById(t.category).name,
      t.type,
      Number(t.amount).toFixed(2),
      t.currency,
      Number(t.amountDefault).toFixed(2),
      `"${String(t.notes || '').replace(/"/g, '""')}"`,
    ].join(','));

    const csv  = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `transactions_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    UI.showToast('CSV exported', 'success');
  },
};

// ================================================================
// BUDGET MODULE
// ================================================================

const Budget = {
  render() {
    const month   = document.getElementById('budget-month').value || App.getCurrentMonth();
    const budgets = App.getBudgets().filter(b => b.month === month);
    const txns    = App.getTransactions().filter(t => t.type === 'expense' && t.date.startsWith(month));

    const totalBudget = budgets.reduce((s, b) => s + b.amount, 0);
    const totalSpent  = txns.reduce((s, t) => s + t.amountDefault, 0);
    const remaining   = totalBudget - totalSpent;

    document.getElementById('budget-total').textContent     = App.formatCurrency(totalBudget);
    document.getElementById('budget-spent').textContent     = App.formatCurrency(totalSpent);
    document.getElementById('budget-remaining').textContent = App.formatCurrency(Math.abs(remaining));
    document.getElementById('budget-remaining').style.color = remaining >= 0 ? 'var(--success)' : 'var(--danger)';

    const el = document.getElementById('budget-list');
    if (!budgets.length) {
      el.innerHTML = '<p class="empty-state">No budgets set for this month. Click "+ Set Budget" to get started.</p>';
      return;
    }

    el.innerHTML = budgets.map(b => {
      const spent    = txns.filter(t => t.category === b.category).reduce((s, t) => s + t.amountDefault, 0);
      const pctRaw   = b.amount > 0 ? (spent / b.amount) * 100 : 0;
      const pctBar   = Math.min(pctRaw, 100);
      const fillCls  = pctRaw >= 100 ? 'over' : pctRaw >= 75 ? 'warn' : 'ok';
      const cat      = App.getCategoryById(b.category);
      return `
        <div class="budget-item">
          <div class="budget-item-header">
            <div class="budget-category">${cat.icon} ${escapeHtml(cat.name)}</div>
            <div class="budget-amounts">
              <span class="${spent > b.amount ? 'amount-expense' : ''}">${App.formatCurrency(spent)}</span>
              <span>/</span>
              <span>${App.formatCurrency(b.amount)}</span>
              <span style="color:${fillCls === 'over' ? 'var(--danger)' : fillCls === 'warn' ? 'var(--warning)' : 'var(--muted)'}">${pctRaw.toFixed(0)}%</span>
              <button class="btn-icon" data-action="edit-budget" data-id="${escapeHtml(b.id)}" title="Edit">✏️</button>
              <button class="btn-icon danger" data-action="del-budget" data-id="${escapeHtml(b.id)}" title="Delete">🗑️</button>
            </div>
          </div>
          <div class="progress-bar">
            <div class="progress-fill ${fillCls}" style="width:${pctBar}%"></div>
          </div>
        </div>`;
    }).join('');
  },

  openAdd() {
    document.getElementById('budget-id').value = '';
    document.getElementById('budget-modal-title').textContent = 'Set Budget';
    document.getElementById('budget-form').reset();
    document.getElementById('budget-month-input').value = document.getElementById('budget-month').value || App.getCurrentMonth();
    UI.populateCategorySelect('budget-category', 'expense');
    UI.showModal('modal-budget');
  },

  openEdit(id) {
    const b = App.getBudgets().find(x => x.id === id);
    if (!b) return;
    document.getElementById('budget-id').value          = b.id;
    document.getElementById('budget-modal-title').textContent = 'Edit Budget';
    UI.populateCategorySelect('budget-category', 'expense', b.category);
    document.getElementById('budget-category').value    = b.category;
    document.getElementById('budget-amount').value      = b.amount;
    document.getElementById('budget-month-input').value = b.month;
    UI.showModal('modal-budget');
  },

  async confirmDelete(id) {
    const ok = await UI.showConfirm('Delete Budget', 'Remove this budget entry?');
    if (!ok) return;
    Storage.saveBudgets(App.user.id, App.getBudgets().filter(b => b.id !== id));
    this.render();
    UI.showToast('Budget deleted', 'success');
  },

  save(e) {
    e.preventDefault();
    const id       = document.getElementById('budget-id').value;
    const category = document.getElementById('budget-category').value;
    const amount   = parseFloat(document.getElementById('budget-amount').value);
    const month    = document.getElementById('budget-month-input').value;

    let budgets = App.getBudgets();
    if (id) {
      budgets = budgets.map(b => b.id === id ? { ...b, category, amount, month } : b);
      UI.showToast('Budget updated', 'success');
    } else {
      const existing = budgets.find(b => b.category === category && b.month === month);
      if (existing) { existing.amount = amount; UI.showToast('Budget updated', 'success'); }
      else { budgets.push({ id: Crypto.generateId(), category, amount, month }); UI.showToast('Budget set', 'success'); }
    }

    Storage.saveBudgets(App.user.id, budgets);
    UI.hideModal('modal-budget');
    this.render();
  },
};

// ================================================================
// BILLS MODULE
// ================================================================

const Bills = {
  render() {
    const bills = App.getBills();
    const tab   = App.billsTab;
    const overdue  = bills.filter(b => !b.paid && UI.daysUntil(b.dueDate) < 0);
    const upcoming = bills.filter(b => !b.paid && UI.daysUntil(b.dueDate) >= 0 && UI.daysUntil(b.dueDate) <= 7);
    const amtDue   = bills.filter(b => !b.paid).reduce((s, b) => s + App.convertToDefault(b.amount, b.currency), 0);

    document.getElementById('bills-overdue-count').textContent = overdue.length;
    document.getElementById('bills-upcoming-count').textContent = upcoming.length;
    document.getElementById('bills-amount-due').textContent    = App.formatCurrency(amtDue);

    let filtered;
    if (tab === 'upcoming') {
      filtered = bills.filter(b => !b.paid).sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate));
    } else if (tab === 'paid') {
      filtered = bills.filter(b => b.paid).sort((a, b) => new Date(b.paidDate || b.dueDate) - new Date(a.paidDate || a.dueDate));
    } else {
      filtered = [...bills].sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate));
    }

    const el = document.getElementById('bills-list');
    if (!filtered.length) {
      el.innerHTML = '<p class="empty-state">No bills in this category.</p>';
      return;
    }

    el.innerHTML = filtered.map(b => {
      const days = UI.daysUntil(b.dueDate);
      let dotCls, metaCls, statusTxt;
      if (b.paid) {
        dotCls = 'paid'; metaCls = ''; statusTxt = `Paid on ${UI.formatDate(b.paidDate || b.dueDate)}`;
      } else if (days < 0) {
        dotCls = 'overdue'; metaCls = 'bill-overdue'; statusTxt = `${Math.abs(days)} day(s) overdue!`;
      } else if (days <= 7) {
        dotCls = 'due-soon'; metaCls = 'bill-due-soon'; statusTxt = days === 0 ? 'Due today!' : `Due in ${days} day(s)`;
      } else {
        dotCls = 'upcoming'; metaCls = ''; statusTxt = `Due ${UI.formatDate(b.dueDate)}`;
      }
      const cat      = App.getCategoryById(b.category);
      const recurring = b.recurring !== 'none' ? ` · ${b.recurring}` : '';
      return `
        <div class="bill-item">
          <div class="bill-status-dot ${dotCls}"></div>
          <div class="bill-info">
            <div class="bill-name">${escapeHtml(b.name)} <span style="font-size:.73rem;color:var(--muted)">${escapeHtml(cat.icon)} ${escapeHtml(cat.name)}${recurring}</span></div>
            <div class="bill-meta ${metaCls}">${statusTxt}</div>
          </div>
          <div class="bill-amount">${App.formatCurrency(App.convertToDefault(b.amount, b.currency))}</div>
          <div class="bill-actions">
            ${!b.paid ? `<button class="btn-icon" data-action="pay-bill" data-id="${escapeHtml(b.id)}" title="Mark as paid">✔️</button>` : ''}
            <button class="btn-icon" data-action="edit-bill" data-id="${escapeHtml(b.id)}" title="Edit">✏️</button>
            <button class="btn-icon danger" data-action="del-bill" data-id="${escapeHtml(b.id)}" title="Delete">🗑️</button>
          </div>
        </div>`;
    }).join('');
  },

  openAdd() {
    document.getElementById('bill-id').value = '';
    document.getElementById('bill-modal-title').textContent = 'Add Bill';
    document.getElementById('bill-form').reset();
    document.getElementById('bill-due-date').value = new Date().toISOString().slice(0, 10);
    UI.populateCurrencySelect('bill-currency', App.settings.currency);
    UI.populateCategorySelect('bill-category', 'expense');
    UI.showModal('modal-bill');
  },

  openEdit(id) {
    const b = App.getBills().find(x => x.id === id);
    if (!b) return;
    document.getElementById('bill-id').value          = b.id;
    document.getElementById('bill-modal-title').textContent = 'Edit Bill';
    document.getElementById('bill-name').value         = b.name;
    document.getElementById('bill-amount').value       = b.amount;
    document.getElementById('bill-due-date').value     = b.dueDate;
    document.getElementById('bill-recurring').value    = b.recurring;
    document.getElementById('bill-notes').value        = b.notes || '';
    UI.populateCurrencySelect('bill-currency', b.currency);
    UI.populateCategorySelect('bill-category', 'expense', b.category);
    document.getElementById('bill-category').value     = b.category;
    UI.showModal('modal-bill');
  },

  markPaid(id) {
    const bills = App.getBills().map(b =>
      b.id === id ? { ...b, paid: true, paidDate: new Date().toISOString().slice(0, 10) } : b
    );
    Storage.saveBills(App.user.id, bills);
    this.render();
    Dashboard.render();
    UI.showToast('Bill marked as paid ✔️', 'success');
  },

  async confirmDelete(id) {
    const ok = await UI.showConfirm('Delete Bill', 'Remove this bill reminder?');
    if (!ok) return;
    Storage.saveBills(App.user.id, App.getBills().filter(b => b.id !== id));
    this.render();
    Dashboard.render();
    UI.showToast('Bill deleted', 'success');
  },

  save(e) {
    e.preventDefault();
    const id        = document.getElementById('bill-id').value;
    const name      = document.getElementById('bill-name').value.trim();
    const amount    = parseFloat(document.getElementById('bill-amount').value);
    const currency  = document.getElementById('bill-currency').value;
    const dueDate   = document.getElementById('bill-due-date').value;
    const category  = document.getElementById('bill-category').value;
    const recurring = document.getElementById('bill-recurring').value;
    const notes     = document.getElementById('bill-notes').value.trim();

    let bills = App.getBills();
    if (id) {
      bills = bills.map(b => b.id === id ? { ...b, name, amount, currency, dueDate, category, recurring, notes } : b);
      UI.showToast('Bill updated', 'success');
    } else {
      bills.push({
        id: Crypto.generateId(), name, amount, currency, dueDate, category,
        recurring, notes, paid: false, paidDate: null, createdAt: new Date().toISOString(),
      });
      UI.showToast('Bill added', 'success');
    }

    Storage.saveBills(App.user.id, bills);
    UI.hideModal('modal-bill');
    this.render();
    Dashboard.render();
  },
};

// ================================================================
// REPORTS MODULE
// ================================================================

const Reports = {
  /** Returns [startDate, endDate] ISO strings based on the period selector */
  _getDateRange() {
    const period = document.getElementById('report-period').value;
    const now    = new Date();
    let start, end;

    if (period === 'this-month') {
      start = new Date(now.getFullYear(), now.getMonth(), 1);
      end   = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    } else if (period === 'last-month') {
      start = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      end   = new Date(now.getFullYear(), now.getMonth(), 0);
    } else if (period === 'last-3') {
      start = new Date(now.getFullYear(), now.getMonth() - 2, 1);
      end   = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    } else if (period === 'last-6') {
      start = new Date(now.getFullYear(), now.getMonth() - 5, 1);
      end   = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    } else { // this-year
      start = new Date(now.getFullYear(), 0, 1);
      end   = new Date(now.getFullYear(), 11, 31);
    }
    return [start.toISOString().slice(0, 10), end.toISOString().slice(0, 10)];
  },

  /** Returns all months (YYYY-MM) between two ISO date strings */
  _monthsInRange(startStr, endStr) {
    const result = [];
    let [y, m]   = startStr.split('-').map(Number);
    const [ey, em] = endStr.split('-').map(Number);
    while (y < ey || (y === ey && m <= em)) {
      result.push(`${y}-${String(m).padStart(2, '0')}`);
      m++; if (m > 12) { m = 1; y++; }
    }
    return result;
  },

  render() {
    const [startDate, endDate] = this._getDateRange();
    const txns   = App.getTransactions().filter(t => t.date >= startDate && t.date <= endDate);
    const months = this._monthsInRange(startDate, endDate);

    const totalIncome  = txns.filter(t => t.type === 'income' ).reduce((s, t) => s + t.amountDefault, 0);
    const totalExpense = txns.filter(t => t.type === 'expense').reduce((s, t) => s + t.amountDefault, 0);
    const avgMonthly   = months.length > 0 ? totalExpense / months.length : 0;

    // Top category
    const byCat = {};
    txns.filter(t => t.type === 'expense').forEach(t => { byCat[t.category] = (byCat[t.category] || 0) + t.amountDefault; });
    const topCatEntry = Object.entries(byCat).sort((a, b) => b[1] - a[1])[0];
    const topCatName  = topCatEntry ? App.getCategoryById(topCatEntry[0]).name : '—';

    document.getElementById('report-income').textContent  = App.formatCurrency(totalIncome);
    document.getElementById('report-expense').textContent = App.formatCurrency(totalExpense);
    document.getElementById('report-avg').textContent     = App.formatCurrency(avgMonthly);
    document.getElementById('report-biggest').textContent = topCatName;

    this._renderCategoryChart(txns, totalExpense);
    this._renderMonthlyChart(txns, months);
    this._renderTrendChart(txns, months);
    this._renderBudgetChart(months);
    this._renderCategoryTable(txns, totalExpense);
  },

  _renderCategoryChart(txns, totalExpense) {
    if (typeof Chart === 'undefined') return;
    UI.destroyChart('repCat');
    const ctx = document.getElementById('report-chart-category');
    if (!ctx) return;
    const expenses  = txns.filter(t => t.type === 'expense');
    const byCat     = {};
    expenses.forEach(t => { byCat[t.category] = (byCat[t.category] || 0) + t.amountDefault; });
    const sorted = Object.entries(byCat).sort((a, b) => b[1] - a[1]).slice(0, 10);

    App.charts.repCat = new Chart(ctx.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: sorted.map(([id]) => App.getCategoryById(id).name),
        datasets: [{ data: sorted.map(([, v]) => v), backgroundColor: CHART_COLORS, borderWidth: 0, hoverOffset: 6 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, boxWidth: 12, padding: 8 } },
          tooltip: { callbacks: { label: c => ` ${App.formatCurrency(c.raw)}  (${totalExpense > 0 ? (c.raw / totalExpense * 100).toFixed(1) : 0}%)` } },
        },
      },
    });
  },

  _renderMonthlyChart(txns, months) {
    if (typeof Chart === 'undefined') return;
    UI.destroyChart('repMonthly');
    const ctx = document.getElementById('report-chart-monthly');
    if (!ctx) return;

    const labels = months.map(m => { const [y, mo] = m.split('-'); return new Date(+y, +mo - 1).toLocaleDateString('en-US', { month: 'short', year: months.length > 6 ? '2-digit' : undefined }); });
    const inc = months.map(m => txns.filter(t => t.type === 'income'  && t.date.startsWith(m)).reduce((s, t) => s + t.amountDefault, 0));
    const exp = months.map(m => txns.filter(t => t.type === 'expense' && t.date.startsWith(m)).reduce((s, t) => s + t.amountDefault, 0));

    App.charts.repMonthly = new Chart(ctx.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'Income',   data: inc, backgroundColor: 'rgba(52,211,153,.7)',  borderRadius: 5 },
          { label: 'Expenses', data: exp, backgroundColor: 'rgba(248,113,113,.7)', borderRadius: 5 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(51,65,85,.4)' } },
          y: { ticks: { color: '#94a3b8', callback: v => App.formatCurrency(v) }, grid: { color: 'rgba(51,65,85,.4)' } },
        },
      },
    });
  },

  _renderTrendChart(txns, months) {
    if (typeof Chart === 'undefined') return;
    UI.destroyChart('repTrend');
    const ctx = document.getElementById('report-chart-trend');
    if (!ctx) return;

    const labels  = months.map(m => { const [y, mo] = m.split('-'); return new Date(+y, +mo - 1).toLocaleDateString('en-US', { month: 'short', year: months.length > 6 ? '2-digit' : undefined }); });
    const expData = months.map(m => txns.filter(t => t.type === 'expense' && t.date.startsWith(m)).reduce((s, t) => s + t.amountDefault, 0));

    App.charts.repTrend = new Chart(ctx.getContext('2d'), {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Monthly Spending', data: expData,
          borderColor: '#38bdf8', backgroundColor: 'rgba(56,189,248,.1)',
          pointBackgroundColor: '#38bdf8', fill: true, tension: 0.4,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(51,65,85,.4)' } },
          y: { ticks: { color: '#94a3b8', callback: v => App.formatCurrency(v) }, grid: { color: 'rgba(51,65,85,.4)' } },
        },
      },
    });
  },

  _renderBudgetChart(months) {
    if (typeof Chart === 'undefined') return;
    UI.destroyChart('repBudget');
    const ctx = document.getElementById('report-chart-budget');
    if (!ctx) return;

    // Use most recent month that has budgets
    const targetMonth = months[months.length - 1] || App.getCurrentMonth();
    const budgets     = App.getBudgets().filter(b => b.month === targetMonth);
    const txns        = App.getTransactions().filter(t => t.type === 'expense' && t.date.startsWith(targetMonth));

    if (!budgets.length) {
      const c2d = ctx.getContext('2d'); c2d.clearRect(0, 0, ctx.width, ctx.height);
      return;
    }

    const labels  = budgets.map(b => App.getCategoryById(b.category).name);
    const budData = budgets.map(b => b.amount);
    const actData = budgets.map(b => txns.filter(t => t.category === b.category).reduce((s, t) => s + t.amountDefault, 0));

    App.charts.repBudget = new Chart(ctx.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'Budget', data: budData, backgroundColor: 'rgba(129,140,248,.7)', borderRadius: 4 },
          { label: 'Actual', data: actData, backgroundColor: 'rgba(248,113,113,.7)', borderRadius: 4 },
        ],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#94a3b8', callback: v => App.formatCurrency(v) }, grid: { color: 'rgba(51,65,85,.4)' } },
          y: { ticks: { color: '#94a3b8' }, grid: { display: false } },
        },
      },
    });
  },

  _renderCategoryTable(txns, totalExpense) {
    const tbody   = document.getElementById('report-categories-table');
    const expenses = txns.filter(t => t.type === 'expense');
    const byCat   = {};
    const countByCat = {};
    expenses.forEach(t => {
      byCat[t.category]      = (byCat[t.category] || 0) + t.amountDefault;
      countByCat[t.category] = (countByCat[t.category] || 0) + 1;
    });

    const sorted = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
    if (!sorted.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No expense data for this period</td></tr>';
      return;
    }

    tbody.innerHTML = sorted.map(([id, amount]) => {
      const cat = App.getCategoryById(id);
      const pct = totalExpense > 0 ? (amount / totalExpense * 100).toFixed(1) : 0;
      return `
        <tr>
          <td>${cat.icon} ${escapeHtml(cat.name)}</td>
          <td class="amount-expense">${App.formatCurrency(amount)}</td>
          <td>${pct}%</td>
          <td>${countByCat[id]}</td>
        </tr>`;
    }).join('');
  },
};

// ================================================================
// SETTINGS MODULE
// ================================================================

const SettingsView = {
  render() {
    const user = App.user;
    document.getElementById('setting-name').value  = user.name  || '';
    document.getElementById('setting-email').value = user.email || '';
    UI.populateCurrencySelect('setting-currency', App.settings.currency);
    this._renderExchangeRates();
  },

  _renderExchangeRates() {
    const rates = App.settings.rates;
    const el    = document.getElementById('exchange-rates-list');
    el.innerHTML = CURRENCIES.map(c => `
      <div class="exchange-rate-row">
        <label for="rate-${c.code}">${c.code}</label>
        <input type="number" id="rate-${c.code}" value="${rates[c.code] || 1}"
               min="0.0001" step="0.0001" ${c.code === 'USD' ? 'disabled' : ''} />
      </div>`
    ).join('');
  },

  saveProfile(e) {
    e.preventDefault();
    const msgEl = document.getElementById('profile-msg');
    const name  = document.getElementById('setting-name').value.trim();
    const email = document.getElementById('setting-email').value.trim();
    if (!name) { msgEl.textContent = 'Name is required'; msgEl.classList.remove('hidden'); return; }
    msgEl.classList.add('hidden');
    App.user.name  = name;
    App.user.email = email;
    Storage.saveUser(App.user);
    document.getElementById('user-name').textContent  = name;
    document.getElementById('user-email').textContent = email;
    document.getElementById('user-avatar').textContent = name.charAt(0).toUpperCase();
    UI.showToast('Profile updated', 'success');
  },

  async changePassword(e) {
    e.preventDefault();
    const errEl    = document.getElementById('pwd-error');
    const currPwd  = document.getElementById('setting-curr-pwd').value;
    const newPwd   = document.getElementById('setting-new-pwd').value;
    const confPwd  = document.getElementById('setting-confirm-pwd').value;

    errEl.classList.add('hidden');
    const currHash = await Crypto.hashPassword(currPwd, App.user.passwordSalt);
    if (currHash !== App.user.passwordHash) {
      errEl.textContent = 'Current password is incorrect'; errEl.classList.remove('hidden'); return;
    }
    if (newPwd.length < 8) {
      errEl.textContent = 'New password must be at least 8 characters'; errEl.classList.remove('hidden'); return;
    }
    if (newPwd !== confPwd) {
      errEl.textContent = 'Passwords do not match'; errEl.classList.remove('hidden'); return;
    }
    const newSalt             = Crypto.generateSalt();
    App.user.passwordHash     = await Crypto.hashPassword(newPwd, newSalt);
    App.user.passwordSalt     = newSalt;
    Storage.saveUser(App.user);
    document.getElementById('password-form').reset();
    UI.showToast('Password updated', 'success');
  },

  saveCurrency() {
    const code       = document.getElementById('setting-currency').value;
    App.settings.currency = code;
    Storage.saveSettings(App.user.id, App.settings);
    UI.showToast(`Default currency set to ${code}`, 'success');
    Dashboard.render();
  },

  saveRates() {
    const rates = {};
    CURRENCIES.forEach(c => {
      const input = document.getElementById(`rate-${c.code}`);
      if (input) rates[c.code] = parseFloat(input.value) || DEFAULT_RATES[c.code];
    });
    App.settings.rates = rates;
    Storage.saveSettings(App.user.id, App.settings);
    UI.showToast('Exchange rates saved', 'success');
  },

  resetRates() {
    App.settings.rates = { ...DEFAULT_RATES };
    Storage.saveSettings(App.user.id, App.settings);
    this._renderExchangeRates();
    UI.showToast('Exchange rates reset to defaults', 'info');
  },

  exportData() {
    const data = Storage.exportAll(App.user.id);
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `financetracker_backup_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    UI.showToast('Data exported', 'success');
  },

  importData(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async e => {
      try {
        const data = JSON.parse(e.target.result);
        const ok   = await UI.showConfirm('Import Data', 'This will merge the imported data with your existing data. Continue?');
        if (!ok) return;
        Storage.importAll(App.user.id, data);
        App.settings = Storage.getSettings(App.user.id);
        Dashboard.render();
        UI.showToast('Data imported successfully', 'success');
      } catch (_) {
        UI.showToast('Invalid JSON file', 'error');
      }
    };
    reader.readAsText(file);
  },

  async clearAllData() {
    const ok = await UI.showConfirm(
      'Clear All Data',
      'This will permanently delete ALL your transactions, budgets, bills, and settings. This cannot be undone.'
    );
    if (!ok) return;
    Storage.clearAllUserData(App.user.id);
    App.settings = Storage.getSettings(App.user.id);
    Dashboard.render();
    UI.showToast('All data cleared', 'warning');
  },
};

// ================================================================
// MAIN INITIALISATION & EVENT WIRING
// ================================================================

async function init() {
  const isLoggedIn = await Auth.init();
  if (isLoggedIn) {
    showApp();
  } else {
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('app').classList.add('hidden');
  }
}

function showApp() {
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  const u = App.user;
  document.getElementById('user-name').textContent   = u.name || u.username;
  document.getElementById('user-email').textContent  = u.email || '';
  document.getElementById('user-avatar').textContent = (u.name || u.username).charAt(0).toUpperCase();

  // Set default month inputs
  const currentMonth = App.getCurrentMonth();
  document.getElementById('budget-month').value   = currentMonth;
  document.getElementById('txn-month-filter').value = '';

  // Populate category filter dropdown
  const catFilter = document.getElementById('txn-cat-filter');
  catFilter.innerHTML = '<option value="">All Categories</option>' +
    CATEGORIES.map(c => `<option value="${c.id}">${c.icon} ${c.name}</option>`).join('');

  UI.showView('dashboard');
  Dashboard.render();

  // Check for overdue bills and alert user
  const overdueBills = App.getBills().filter(b => !b.paid && UI.daysUntil(b.dueDate) < 0);
  if (overdueBills.length > 0) {
    setTimeout(() => UI.showToast(`You have ${overdueBills.length} overdue bill(s)!`, 'warning', 5000), 800);
  }
}

function wireEvents() {
  // ── Auth ────────────────────────────────────
  document.querySelectorAll('.auth-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const isLogin = tab.dataset.tab === 'login';
      document.getElementById('login-form').classList.toggle('hidden', !isLogin);
      document.getElementById('register-form').classList.toggle('hidden', isLogin);
    });
  });

  document.getElementById('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    const errEl = document.getElementById('login-error');
    errEl.classList.add('hidden');
    try {
      await Auth.login(
        document.getElementById('login-username').value.trim(),
        document.getElementById('login-password').value
      );
      showApp();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove('hidden');
    }
  });

  document.getElementById('register-form').addEventListener('submit', async e => {
    e.preventDefault();
    const errEl   = document.getElementById('reg-error');
    const pwd     = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;
    errEl.classList.add('hidden');
    if (pwd.length < 8) { errEl.textContent = 'Password must be at least 8 characters'; errEl.classList.remove('hidden'); return; }
    if (pwd !== confirm) { errEl.textContent = 'Passwords do not match'; errEl.classList.remove('hidden'); return; }
    try {
      await Auth.register(
        document.getElementById('reg-name').value.trim(),
        document.getElementById('reg-username').value.trim(),
        document.getElementById('reg-email').value.trim(),
        pwd
      );
      showApp();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove('hidden');
    }
  });

  document.getElementById('logout-btn').addEventListener('click', () => {
    Auth.logout();
    document.getElementById('app').classList.add('hidden');
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('login-form').reset();
    document.getElementById('login-error').classList.add('hidden');
  });

  // ── Sidebar navigation ───────────────────────
  document.querySelectorAll('.nav-item, .link-sm[data-view]').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      const view = el.dataset.view;
      if (!view) return;
      UI.showView(view);
      if (view === 'dashboard')    Dashboard.render();
      if (view === 'transactions') Transactions.render();
      if (view === 'budget')       Budget.render();
      if (view === 'bills')        Bills.render();
      if (view === 'reports')      Reports.render();
      if (view === 'settings')     SettingsView.render();
    });
  });

  // ── Mobile sidebar toggle ────────────────────
  const sidebar  = document.getElementById('sidebar');
  const overlay  = document.getElementById('sidebar-overlay');
  const menuBtn  = document.getElementById('menu-toggle');
  const closeBtn = document.getElementById('sidebar-close');

  const openSidebar  = () => { sidebar.classList.add('open'); overlay.classList.add('visible'); };
  const closeSidebar = () => { sidebar.classList.remove('open'); overlay.classList.remove('visible'); };

  menuBtn.addEventListener('click', openSidebar);
  closeBtn.addEventListener('click', closeSidebar);
  overlay.addEventListener('click', closeSidebar);

  // ── Modal close buttons ──────────────────────
  document.querySelectorAll('[data-modal]').forEach(btn => {
    btn.addEventListener('click', () => UI.hideModal(btn.dataset.modal));
  });
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) UI.hideModal(overlay.id);
    });
  });

  // ── Dashboard ────────────────────────────────
  document.getElementById('quick-add-btn').addEventListener('click', () => Transactions.openAdd());

  // ── Transactions ─────────────────────────────
  document.getElementById('add-transaction-btn').addEventListener('click', () => Transactions.openAdd());
  document.getElementById('export-csv-btn').addEventListener('click', () => Transactions.exportCSV());
  document.getElementById('transaction-form').addEventListener('submit', e => Transactions.save(e));
  document.getElementById('txn-type').addEventListener('change', () => {
    UI.populateCategorySelect('txn-category', document.getElementById('txn-type').value);
  });

  // Filters
  const filterChange = () => {
    App.txnPage     = 1;
    App.txnFilters  = {
      search:   document.getElementById('txn-search').value.trim(),
      type:     document.getElementById('txn-type-filter').value,
      category: document.getElementById('txn-cat-filter').value,
      month:    document.getElementById('txn-month-filter').value,
    };
    Transactions.render();
  };
  ['txn-search', 'txn-type-filter', 'txn-cat-filter', 'txn-month-filter'].forEach(id =>
    document.getElementById(id).addEventListener('input', filterChange)
  );
  document.getElementById('clear-filters-btn').addEventListener('click', () => {
    document.getElementById('txn-search').value       = '';
    document.getElementById('txn-type-filter').value  = '';
    document.getElementById('txn-cat-filter').value   = '';
    document.getElementById('txn-month-filter').value = '';
    App.txnFilters = { search: '', type: '', category: '', month: '' };
    App.txnPage    = 1;
    Transactions.render();
  });

  // ── Budget ────────────────────────────────────
  document.getElementById('add-budget-btn').addEventListener('click', () => Budget.openAdd());
  document.getElementById('budget-form').addEventListener('submit', e => Budget.save(e));
  document.getElementById('budget-month').addEventListener('change', () => Budget.render());

  // ── Bills ─────────────────────────────────────
  document.getElementById('add-bill-btn').addEventListener('click', () => Bills.openAdd());
  document.getElementById('bill-form').addEventListener('submit', e => Bills.save(e));
  document.querySelectorAll('.bills-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.bills-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      App.billsTab = tab.dataset.status;
      Bills.render();
    });
  });

  // ── Reports ───────────────────────────────────
  document.getElementById('report-period').addEventListener('change', () => Reports.render());
  document.getElementById('export-pdf-btn').addEventListener('click', () => {
    UI.showToast('Opening print dialog…', 'info', 2000);
    setTimeout(() => window.print(), 600);
  });

  // ── Settings ──────────────────────────────────
  document.getElementById('profile-form').addEventListener('submit', e => SettingsView.saveProfile(e));
  document.getElementById('password-form').addEventListener('submit', e => SettingsView.changePassword(e));
  document.getElementById('save-currency-btn').addEventListener('click', () => SettingsView.saveCurrency());
  document.getElementById('save-rates-btn').addEventListener('click', () => SettingsView.saveRates());
  document.getElementById('reset-rates-btn').addEventListener('click', () => SettingsView.resetRates());
  document.getElementById('export-data-btn').addEventListener('click', () => SettingsView.exportData());
  document.getElementById('import-data-btn').addEventListener('click', () => document.getElementById('import-file').click());
  document.getElementById('import-file').addEventListener('change', e => {
    SettingsView.importData(e.target.files[0]);
    e.target.value = '';
  });
  // ── Event delegation for dynamically rendered list actions ──────
  // Transactions table: edit / delete rows
  document.getElementById('transactions-table-body').addEventListener('click', e => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.action === 'edit-txn') Transactions.openEdit(id);
    if (btn.dataset.action === 'del-txn')  Transactions.confirmDelete(id);
  });

  // Transactions pagination
  document.getElementById('txn-pagination').addEventListener('click', e => {
    const btn = e.target.closest('[data-page]');
    if (!btn || btn.disabled) return;
    Transactions.goPage(Number(btn.dataset.page));
  });

  // Budget list: edit / delete items
  document.getElementById('budget-list').addEventListener('click', e => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.action === 'edit-budget') Budget.openEdit(id);
    if (btn.dataset.action === 'del-budget')  Budget.confirmDelete(id);
  });

  // Bills list: pay / edit / delete items
  document.getElementById('bills-list').addEventListener('click', e => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.action === 'pay-bill')  Bills.markPaid(id);
    if (btn.dataset.action === 'edit-bill') Bills.openEdit(id);
    if (btn.dataset.action === 'del-bill')  Bills.confirmDelete(id);
  });
}

// ── Kick-off ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  wireEvents();
  init();
});
