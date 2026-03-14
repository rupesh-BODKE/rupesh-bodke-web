// ── Finance Tracker App ─────────────────────────────────────
// Manages transactions, balances, and Chart.js visualisation.
// Data is persisted to localStorage.

(function () {
  'use strict';

  // ── DOM References ──────────────────────────────────────
  const form            = document.getElementById('transaction-form');
  const descInput       = document.getElementById('description');
  const amountInput     = document.getElementById('amount');
  const typeSelect      = document.getElementById('type');
  const categorySelect  = document.getElementById('category');
  const listEl          = document.getElementById('transaction-list');
  const balanceEl       = document.getElementById('balance');
  const incomeEl        = document.getElementById('income');
  const expenseEl       = document.getElementById('expense');
  const filterTypeEl    = document.getElementById('filter-type');
  const searchEl        = document.getElementById('search');
  const chartCanvas     = document.getElementById('expense-chart');
  const noDataMsg       = document.getElementById('no-data');

  // ── State ───────────────────────────────────────────────
  const STORAGE_KEY = 'financeTrackerTransactions';
  let transactions  = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  let chart         = null;

  // ── Category Definitions ────────────────────────────────
  const CATEGORIES = {
    income:  ['Salary', 'Freelance', 'Investment', 'Gift', 'Other'],
    expense: ['Food', 'Transport', 'Housing', 'Utilities', 'Entertainment', 'Health', 'Shopping', 'Education', 'Other']
  };

  const CATEGORY_COLORS = {
    Salary:        '#22c55e',
    Freelance:     '#10b981',
    Investment:    '#14b8a6',
    Gift:          '#06b6d4',
    Food:          '#ef4444',
    Transport:     '#f97316',
    Housing:       '#eab308',
    Utilities:     '#a855f7',
    Entertainment: '#ec4899',
    Health:        '#3b82f6',
    Shopping:      '#f43f5e',
    Education:     '#6366f1',
    Other:         '#94a3b8'
  };

  // ── Helpers ─────────────────────────────────────────────
  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  }

  function save() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(transactions));
  }

  function formatCurrency(n) {
    return (n < 0 ? '-' : '') + '$' + Math.abs(n).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  // ── Populate Category Dropdown ──────────────────────────
  function populateCategories() {
    var type = typeSelect.value;
    categorySelect.innerHTML = '';
    (CATEGORIES[type] || []).forEach(function (cat) {
      var opt   = document.createElement('option');
      opt.value = cat;
      opt.textContent = cat;
      categorySelect.appendChild(opt);
    });
  }

  typeSelect.addEventListener('change', populateCategories);
  populateCategories();

  // ── Compute & Render Summary ────────────────────────────
  function updateSummary() {
    var income  = 0;
    var expense = 0;

    transactions.forEach(function (t) {
      if (t.type === 'income') {
        income += t.amount;
      } else {
        expense += t.amount;
      }
    });

    balanceEl.textContent  = formatCurrency(income - expense);
    incomeEl.textContent   = formatCurrency(income);
    expenseEl.textContent  = formatCurrency(expense);

    balanceEl.className = 'summary-value ' + ((income - expense) >= 0 ? 'positive' : 'negative');
  }

  // ── Filter Transactions ─────────────────────────────────
  function getFilteredTransactions() {
    var filterType  = filterTypeEl.value;
    var searchTerm  = searchEl.value.toLowerCase().trim();

    return transactions.filter(function (t) {
      var matchesType = filterType === 'all' || t.type === filterType;
      var matchesSearch = !searchTerm ||
        t.description.toLowerCase().includes(searchTerm) ||
        t.category.toLowerCase().includes(searchTerm);
      return matchesType && matchesSearch;
    });
  }

  // ── Render Transaction List ─────────────────────────────
  function renderList() {
    var filtered = getFilteredTransactions();
    listEl.innerHTML = '';

    if (filtered.length === 0) {
      noDataMsg.style.display = 'block';
    } else {
      noDataMsg.style.display = 'none';
    }

    filtered.forEach(function (t) {
      var li = document.createElement('li');
      li.className = 'transaction-item ' + t.type;
      li.innerHTML =
        '<div class="transaction-info">' +
          '<span class="transaction-category-badge" style="background:' + (CATEGORY_COLORS[t.category] || '#94a3b8') + '20; color:' + (CATEGORY_COLORS[t.category] || '#94a3b8') + '">' + escapeHtml(t.category) + '</span>' +
          '<span class="transaction-desc">' + escapeHtml(t.description) + '</span>' +
          '<span class="transaction-date">' + t.date + '</span>' +
        '</div>' +
        '<div class="transaction-actions">' +
          '<span class="transaction-amount ' + t.type + '">' + (t.type === 'income' ? '+' : '-') + formatCurrency(t.amount) + '</span>' +
          '<button class="btn-delete" data-id="' + t.id + '" title="Delete transaction" aria-label="Delete transaction">&times;</button>' +
        '</div>';
      listEl.appendChild(li);
    });
  }

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  // ── Delete Handler (event delegation) ───────────────────
  listEl.addEventListener('click', function (e) {
    if (e.target.classList.contains('btn-delete')) {
      var id = e.target.getAttribute('data-id');
      transactions = transactions.filter(function (t) { return t.id !== id; });
      save();
      render();
    }
  });

  // ── Chart ───────────────────────────────────────────────
  function renderChart() {
    var expenseTotals = {};

    transactions.forEach(function (t) {
      if (t.type === 'expense') {
        expenseTotals[t.category] = (expenseTotals[t.category] || 0) + t.amount;
      }
    });

    var labels = Object.keys(expenseTotals);
    var data   = Object.values(expenseTotals);
    var colors = labels.map(function (l) { return CATEGORY_COLORS[l] || '#94a3b8'; });

    if (chart) {
      chart.destroy();
    }

    if (labels.length === 0) {
      chartCanvas.style.display = 'none';
      return;
    }

    if (typeof Chart === 'undefined') {
      return;
    }

    chartCanvas.style.display = 'block';

    chart = new Chart(chartCanvas, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderColor: '#1e293b',
          borderWidth: 3,
          hoverBorderColor: '#0f172a'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#e2e8f0',
              padding: 16,
              usePointStyle: true,
              pointStyleWidth: 12,
              font: { size: 13 }
            }
          },
          tooltip: {
            backgroundColor: '#1e293b',
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            borderColor: '#334155',
            borderWidth: 1,
            padding: 12,
            callbacks: {
              label: function (ctx) {
                var total = ctx.dataset.data.reduce(function (a, b) { return a + b; }, 0);
                var pct   = ((ctx.parsed / total) * 100).toFixed(1);
                return ctx.label + ': ' + formatCurrency(ctx.parsed) + ' (' + pct + '%)';
              }
            }
          }
        }
      }
    });
  }

  // ── Master Render ───────────────────────────────────────
  function render() {
    updateSummary();
    renderList();
    renderChart();
  }

  // ── Form Submit ─────────────────────────────────────────
  form.addEventListener('submit', function (e) {
    e.preventDefault();

    var desc   = descInput.value.trim();
    var amount = parseFloat(amountInput.value);

    if (!desc || isNaN(amount) || amount <= 0) {
      return;
    }

    transactions.unshift({
      id:          generateId(),
      description: desc,
      amount:      amount,
      type:        typeSelect.value,
      category:    categorySelect.value,
      date:        new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    });

    save();
    render();
    form.reset();
    populateCategories();
  });

  // ── Filter / Search Listeners ───────────────────────────
  filterTypeEl.addEventListener('change', renderList);
  searchEl.addEventListener('input', renderList);

  // ── Initial Render ──────────────────────────────────────
  render();
})();
