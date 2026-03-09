// Loading overlay
window.addEventListener('load', () => {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) { setTimeout(() => { overlay.classList.add('hide'); setTimeout(() => overlay.remove(), 300); }, 600); }
});

// Sidebar toggle
const sidebar = document.getElementById('sidebar');
const sidebarBtn = document.getElementById('sidebar-toggle-btn');
if (sidebarBtn) {
  sidebarBtn.addEventListener('click', () => sidebar.classList.toggle('expanded'));
}

// Notification dropdown
const notifBtn = document.getElementById('notif-btn');
const notifDrop = document.getElementById('notif-dropdown');
if (notifBtn && notifDrop) {
  notifBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    notifDrop.classList.toggle('show');
  });
  document.addEventListener('click', () => notifDrop.classList.remove('show'));
}

// Filter chips (homepage queue)
document.querySelectorAll('.filter-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    const filter = chip.dataset.filter;
    const rows = document.querySelectorAll('.case-row');
    const cards = document.querySelectorAll('.case-card');
    let count = 0;

    rows.forEach(row => {
      const status = row.dataset.status;
      const show = filter === 'all' || status === filter;
      row.style.display = show ? '' : 'none';
      if (show) count++;
    });

    cards.forEach(card => {
      const status = card.dataset.status;
      const show = filter === 'all' || status === filter;
      card.style.display = show ? '' : 'none';
    });

    const countEl = document.getElementById('case-count');
    if (countEl) countEl.textContent = count;
  });
});

// View toggle (list/card)
const btnList = document.getElementById('btn-list-view');
const btnCard = document.getElementById('btn-card-view');
const tableView = document.getElementById('table-view');
const cardView = document.getElementById('card-view');

if (btnList && btnCard) {
  btnList.addEventListener('click', () => {
    btnList.classList.add('active'); btnCard.classList.remove('active');
    tableView.classList.remove('hidden'); cardView.classList.remove('active');
  });
  btnCard.addEventListener('click', () => {
    btnCard.classList.add('active'); btnList.classList.remove('active');
    tableView.classList.add('hidden'); cardView.classList.add('active');
  });
}

// Case detail tabs
document.querySelectorAll('.cd-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.cd-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
    tab.classList.add('active');
    const target = document.getElementById('tab-' + tab.dataset.tab);
    if (target) target.classList.add('active');
  });
});

// Detail sidebar toggle
const toggleSidebar = document.getElementById('toggle-detail-sidebar');
const detailSidebar = document.getElementById('detail-sidebar');
if (toggleSidebar && detailSidebar) {
  toggleSidebar.addEventListener('click', () => detailSidebar.classList.toggle('collapsed'));
}

// Global search + command palette
const searchInput = document.getElementById('global-search');
if (searchInput) {
  const isIocPage = !!document.getElementById('ioc-view');
  const baseUrl = document.querySelector('meta[name="base-url"]')?.content || '/';

  // Command palette
  const commands = [
    { name: 'home', desc: 'Go to dashboard', path: '' },
    { name: 'cases', desc: 'Browse all cases', path: 'cases/' },
    { name: 'iocs', desc: 'IOC Database', path: 'iocs/' },
    { name: 'mitre', desc: 'MITRE ATT&CK Matrix', path: 'mitre/' },
    { name: 'actors', desc: 'Threat Actors', path: 'actors/' },
  ];

  // Create command dropdown
  const cmdPalette = document.createElement('div');
  cmdPalette.className = 'cmd-palette';
  searchInput.closest('.search-box').appendChild(cmdPalette);
  let cmdIndex = 0;

  function renderCommands(filter) {
    const q = filter.toLowerCase();
    const matches = commands.filter(c => c.name.includes(q) || c.desc.toLowerCase().includes(q));
    cmdIndex = 0;
    if (!matches.length) {
      cmdPalette.innerHTML = '<div class="cmd-empty">No matching commands</div>';
      return;
    }
    cmdPalette.innerHTML = matches.map((c, i) =>
      `<div class="cmd-item${i === 0 ? ' active' : ''}" data-path="${c.path}">` +
      `<span class="cmd-name">/${c.name}</span>` +
      `<span class="cmd-desc">${c.desc}</span>` +
      `</div>`
    ).join('');
    cmdPalette.querySelectorAll('.cmd-item').forEach(item => {
      item.addEventListener('click', () => {
        window.location = baseUrl + item.dataset.path;
      });
    });
  }

  function showPalette(filter) {
    renderCommands(filter);
    cmdPalette.classList.add('show');
  }

  function hidePalette() {
    cmdPalette.classList.remove('show');
  }

  searchInput.addEventListener('input', () => {
    const val = searchInput.value;

    if (val.startsWith('/')) {
      showPalette(val.slice(1));
      return;
    }

    hidePalette();
    const q = val.toLowerCase();

    if (isIocPage) {
      document.querySelectorAll('.ioc-row').forEach(row => {
        const v = row.querySelector('.ioc-val')?.textContent.toLowerCase() || '';
        const desc = row.querySelectorAll('td')[2]?.textContent.toLowerCase() || '';
        row.style.display = (v.includes(q) || desc.includes(q)) ? '' : 'none';
      });
    } else {
      document.querySelectorAll('.case-row').forEach(row => {
        const title = row.dataset.title?.toLowerCase() || '';
        const iocs = row.dataset.iocs?.toLowerCase() || '';
        row.style.display = (title.includes(q) || iocs.includes(q)) ? '' : 'none';
      });
      document.querySelectorAll('.case-card').forEach(card => {
        const title = card.querySelector('.case-card-title')?.textContent.toLowerCase() || '';
        const iocs = card.dataset.iocs?.toLowerCase() || '';
        card.style.display = (title.includes(q) || iocs.includes(q)) ? '' : 'none';
      });
    }
  });

  searchInput.addEventListener('keydown', (e) => {
    if (!cmdPalette.classList.contains('show')) return;
    const items = cmdPalette.querySelectorAll('.cmd-item');
    if (!items.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      items[cmdIndex]?.classList.remove('active');
      cmdIndex = (cmdIndex + 1) % items.length;
      items[cmdIndex]?.classList.add('active');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      items[cmdIndex]?.classList.remove('active');
      cmdIndex = (cmdIndex - 1 + items.length) % items.length;
      items[cmdIndex]?.classList.add('active');
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const active = items[cmdIndex];
      if (active) window.location = baseUrl + active.dataset.path;
    }
  });

  // Close palette on blur
  searchInput.addEventListener('blur', () => setTimeout(hidePalette, 150));

  // "/" keyboard shortcut
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
      e.preventDefault();
      searchInput.focus();
    }
    if (e.key === 'Escape') { hidePalette(); searchInput.blur(); }
  });
}

// Image lightbox
const lightbox = document.getElementById('lightbox');
const lightboxImg = lightbox ? lightbox.querySelector('img') : null;
const lightboxCaption = document.getElementById('lightbox-caption');

if (lightbox && lightboxImg) {
  // Attach click handlers to all images inside investigation content
  document.querySelectorAll('.investigation-content img').forEach(img => {
    img.addEventListener('click', () => {
      lightboxImg.src = img.src;
      lightboxImg.alt = img.alt;
      if (img.alt && lightboxCaption) {
        lightboxCaption.textContent = img.alt;
        lightboxCaption.style.display = 'block';
      } else if (lightboxCaption) {
        lightboxCaption.style.display = 'none';
      }
      lightbox.classList.add('active');
    });
  });

  // Close lightbox on click
  lightbox.addEventListener('click', () => {
    lightbox.classList.remove('active');
  });

  // Close lightbox on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && lightbox.classList.contains('active')) {
      lightbox.classList.remove('active');
    }
  });
}
