(() => {
  'use strict';

  const policy = document.querySelector('[data-password-policy]');
  const password = document.querySelector('[name="new_password1"]');
  const confirmation = document.querySelector('[name="new_password2"]');
  if (!policy || !password || !confirmation) return;

  const rules = {
    min: (value) => value.length >= Number(policy.dataset.minLength),
    uppercase: (value) => /[A-Z]/.test(value),
    lowercase: (value) => /[a-z]/.test(value),
    number: (value) => /\d/.test(value),
    special: (value) => /[^A-Za-z0-9]/.test(value),
  };
  const status = document.querySelector('[data-password-match-status]');

  function update() {
    const value = password.value;
    policy.querySelectorAll('[data-password-rule]').forEach((item) => {
      const valid = rules[item.dataset.passwordRule](value);
      item.classList.toggle('is-met', Boolean(value) && valid);
      item.classList.toggle('is-unmet', Boolean(value) && !valid);
    });
    if (!confirmation.value) {
      status.textContent = '';
      status.className = 'password-match-status';
      return;
    }
    const matches = value === confirmation.value;
    status.textContent = matches ? 'As senhas coincidem.' : 'As senhas não coincidem.';
    status.className = `password-match-status ${matches ? 'is-met' : 'is-unmet'}`;
  }

  password.addEventListener('input', update);
  confirmation.addEventListener('input', update);
})();
