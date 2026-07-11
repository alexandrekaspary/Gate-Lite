(() => {
  'use strict';

  const body = document.body;
  const toggle = document.querySelector('.menu-toggle');
  const sidebar = document.querySelector('.sidebar');
  const closeTargets = document.querySelectorAll('[data-sidebar-close]');

  const setSidebar = (open) => {
    body.classList.toggle('sidebar-open', open);
    toggle?.setAttribute('aria-expanded', String(open));
    toggle?.setAttribute('aria-label', open ? 'Fechar menu' : 'Abrir menu');
    if (open) sidebar?.querySelector('a')?.focus();
  };

  toggle?.addEventListener('click', () => setSidebar(!body.classList.contains('sidebar-open')));
  closeTargets.forEach((target) => target.addEventListener('click', () => setSidebar(false)));
  sidebar?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
    if (window.matchMedia('(max-width: 960px)').matches) setSidebar(false);
  }));
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && body.classList.contains('sidebar-open')) {
      setSidebar(false);
      toggle?.focus();
    }
  });

  const searchIcon = '<svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>';
  document.querySelectorAll('select[multiple]:not([data-no-enhance])').forEach((select) => {
    if (select.closest('.select-enhanced')) return;
    const field = select.closest('.field-wrapper, .setting-field');
    const visibleLabel = field?.querySelector('label:not(.checkbox-control)')?.textContent?.replace('*', '').trim() || 'opções';
    const wrapper = document.createElement('div');
    wrapper.className = 'select-enhanced';
    select.parentNode.insertBefore(wrapper, select);

    const search = document.createElement('div');
    search.className = 'select-search';
    search.innerHTML = `${searchIcon}<input type="search" autocomplete="off" placeholder="Filtrar opções…" aria-label="Filtrar ${visibleLabel}"><span class="selection-count" aria-live="polite"></span>`;
    wrapper.append(search, select);
    const empty = document.createElement('span');
    empty.className = 'select-empty';
    empty.textContent = 'Nenhuma opção corresponde à busca.';
    wrapper.append(empty);

    const input = search.querySelector('input');
    const count = search.querySelector('.selection-count');
    const options = [...select.options];
    const updateCount = () => {
      const selected = options.filter((option) => option.selected).length;
      count.textContent = selected ? `${selected} selecionada${selected === 1 ? '' : 's'}` : 'Nenhuma';
    };
    const filterOptions = () => {
      const query = input.value.trim().toLocaleLowerCase('pt-BR');
      let visible = 0;
      options.forEach((option) => {
        const matches = !query || option.text.toLocaleLowerCase('pt-BR').includes(query);
        option.hidden = !matches;
        if (matches) visible += 1;
      });
      wrapper.classList.toggle('no-results', visible === 0);
    };
    input.addEventListener('input', filterOptions);
    select.addEventListener('change', updateCount);
    updateCount();
  });
})();
