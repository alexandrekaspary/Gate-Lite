(() => {
  'use strict';

  document.querySelectorAll('[data-confirm]').forEach((element) => {
    element.addEventListener('submit', (event) => {
      if (!window.confirm(element.dataset.confirm)) event.preventDefault();
    });
  });

  document.querySelectorAll('.alert-close').forEach((button) => {
    button.addEventListener('click', () => {
      const alert = button.closest('.alert');
      if (alert) alert.remove();
    });
  });

  const writeClipboard = async (value) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const area = document.createElement('textarea');
    area.value = value;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  };

  document.querySelectorAll('[data-copy-target], [data-copy-value]').forEach((button) => {
    button.addEventListener('click', async () => {
      const target = button.dataset.copyTarget ? document.querySelector(button.dataset.copyTarget) : null;
      const value = button.dataset.copyValue || target?.textContent?.trim() || '';
      if (!value) return;
      const label = button.querySelector('span');
      const original = label?.textContent;
      try {
        await writeClipboard(value);
        button.classList.add('copied');
        if (label) label.textContent = 'Copiado';
        window.setTimeout(() => {
          button.classList.remove('copied');
          if (label) label.textContent = original;
        }, 1800);
      } catch (_) {
        if (label) label.textContent = 'Não foi possível copiar';
      }
    });
  });

  const eyeIcon = '<svg aria-hidden="true" viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
  const eyeOffIcon = '<svg aria-hidden="true" viewBox="0 0 24 24"><path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 4.2A10.7 10.7 0 0 1 12 4c6.5 0 10 8 10 8a18 18 0 0 1-2 3M6.6 6.6C3.5 8.6 2 12 2 12s3.5 8 10 8a9.8 9.8 0 0 0 4-.8"/></svg>';

  document.querySelectorAll('input[type="password"]').forEach((input) => {
    input.autocomplete = /old|current|^password$/i.test(input.name) ? 'current-password' : 'new-password';
    if (input.parentElement?.querySelector('.password-toggle')) return;
    let control = input.parentElement;
    if (!control?.classList.contains('input-icon-wrap')) {
      control = document.createElement('div');
      control.className = 'password-input-control';
      input.parentNode.insertBefore(control, input);
      control.append(input);
    }
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'password-toggle';
    button.setAttribute('aria-label', 'Mostrar senha');
    button.setAttribute('aria-pressed', 'false');
    button.innerHTML = eyeIcon;
    button.addEventListener('click', () => {
      const visible = input.type === 'text';
      input.type = visible ? 'password' : 'text';
      button.setAttribute('aria-label', visible ? 'Mostrar senha' : 'Ocultar senha');
      button.setAttribute('aria-pressed', String(!visible));
      button.innerHTML = visible ? eyeIcon : eyeOffIcon;
    });
    control.append(button);
  });
})();
