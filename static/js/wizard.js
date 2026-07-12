(() => {
  'use strict';

  const form = document.querySelector('.wizard-form');
  if (!form) return;

  const definitions = {
    users: [
      { title: 'Identidade', description: 'Dados pessoais', fields: ['username', 'first_name', 'last_name', 'email', 'language', 'timezone'] },
      { title: 'Segurança', description: 'Credenciais e segundo fator', fields: ['password1', 'password2', 'new_password', 'new_password_confirmation', 'password', 'is_active', 'must_change_password', 'required_actions', 'reset_mfa'] },
      { title: 'Acessos', description: 'Grupos e roles', fields: ['groups', 'client_roles', 'direct_roles', 'roles', 'role_assignments'] },
      { title: 'Administração', description: 'Privilégios internos', fields: ['basic_access', 'is_staff', 'is_superuser', 'user_permissions', 'permissions'] }
    ],
    groups: [
      { title: 'Identificação', description: 'Dados do grupo', fields: ['name', 'description'] },
      { title: 'Membros', description: 'Usuários vinculados', fields: ['users', 'members'] },
      { title: 'Roles de clients', description: 'Acesso às aplicações', fields: ['client_roles', 'roles'] },
      { title: 'Administração', description: 'Permissões do console', fields: ['permissions'] }
    ],
    clients: [
      { title: 'Identificação', description: 'Nome, ID e tipo', fields: ['name', 'client_id', 'application_type', 'client_type', 'is_confidential', 'is_active'] },
      { title: 'Protocolo', description: 'Fluxos e scopes', fields: ['grant_types', 'allowed_grant_types', 'authorization_code_enabled', 'refresh_token_enabled', 'client_credentials_enabled', 'require_pkce', 'scopes', 'response_types', 'token_endpoint_auth_method'] },
      { title: 'URLs', description: 'Redirecionamentos', fields: ['redirect_uris', 'post_logout_redirect_uris', 'web_origins', 'allowed_origins', 'cors_origins'] },
      { title: 'Acesso', description: 'Políticas e credenciais', fields: ['allowed_groups', 'allowed_users', 'allowed_audiences', 'groups', 'generate_secret', 'service_account', 'access_policy', 'require_mfa'] }
    ],
    roles: [
      { title: 'Role', description: 'Client e identificação', fields: ['client', 'name', 'description', 'is_default'] },
      { title: 'Atribuições', description: 'Grupos, usuários e serviços', fields: ['groups', 'users', 'service_clients', 'composites', 'composite_roles'] }
    ]
  };

  const steps = definitions[form.dataset.kind];
  const fieldsContainer = form.querySelector('.form-fields');
  const anchor = form.querySelector('.wizard-anchor');
  if (!steps || !fieldsContainer || !anchor) return;

  const wrappers = [...fieldsContainer.querySelectorAll(':scope > .field-wrapper')];
  if (wrappers.length < 2) return;

  const assignments = new Map();
  wrappers.forEach((wrapper) => {
    const name = wrapper.dataset.field;
    let stepIndex = steps.findIndex((step) => step.fields.includes(name));
    if (stepIndex < 0) {
      if (/password|credential|secret/i.test(name)) stepIndex = Math.min(1, steps.length - 1);
      else if (/role|group|permission|member|access/i.test(name)) stepIndex = Math.max(0, steps.length - 2);
      else stepIndex = steps.length - 1;
    }
    assignments.set(wrapper, stepIndex);
  });

  const usedSteps = steps
    .map((step, originalIndex) => ({ ...step, originalIndex }))
    .filter((step) => [...assignments.values()].includes(step.originalIndex));
  if (usedSteps.length < 2) return;

  form.noValidate = true;
  const nav = document.createElement('nav');
  nav.className = 'wizard-steps';
  nav.setAttribute('aria-label', 'Etapas do formulário');
  anchor.replaceWith(nav);
  const panels = [];
  const buttons = [];

  usedSteps.forEach((step, index) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'wizard-step';
    button.setAttribute('aria-controls', `wizard-panel-${index + 1}`);
    button.innerHTML = `<span class="wizard-step-number">${index + 1}</span><span class="wizard-step-copy"><strong>${step.title}</strong><small>${step.description}</small></span>`;
    nav.append(button);
    buttons.push(button);

    const panel = document.createElement('section');
    panel.className = 'wizard-panel';
    panel.id = `wizard-panel-${index + 1}`;
    panel.setAttribute('aria-labelledby', `wizard-step-${index + 1}`);
    button.id = `wizard-step-${index + 1}`;
    const heading = document.createElement('div');
    heading.className = 'wizard-panel-header';
    heading.innerHTML = `<h3>${step.title}</h3><p>${step.description}</p>`;
    panel.append(heading);
    wrappers
      .filter((wrapper) => assignments.get(wrapper) === step.originalIndex)
      .forEach((wrapper) => panel.append(wrapper));
    panels.push(panel);
    fieldsContainer.before(panel);
    button.addEventListener('click', () => show(index));
  });

  fieldsContainer.remove();

  const previous = form.querySelector('.wizard-prev');
  const next = form.querySelector('.wizard-next');
  const save = form.querySelector('.wizard-save');
  previous.hidden = false;
  next.hidden = false;

  let current = 0;
  let furthest = 0;

  const firstInvalid = (panel) => [...panel.querySelectorAll('input, select, textarea')]
    .find((control) => !control.disabled && !control.checkValidity());

  const refreshStates = () => {
    panels.forEach((panel, index) => {
      const active = index === current;
      panel.hidden = !active;
      buttons[index].classList.toggle('active', active);
      buttons[index].classList.toggle('complete', index < furthest && !panel.querySelector('.field-error'));
      buttons[index].classList.toggle('has-errors', Boolean(panel.querySelector('.field-error')));
      buttons[index].setAttribute('aria-current', active ? 'step' : 'false');
    });
    previous.style.visibility = current === 0 ? 'hidden' : 'visible';
    next.hidden = current === panels.length - 1;
    save.hidden = current !== panels.length - 1;
  };

  function show(index, focus = false) {
    current = Math.max(0, Math.min(index, panels.length - 1));
    furthest = Math.max(furthest, current);
    refreshStates();
    if (focus) panels[current].querySelector('input:not([type="hidden"]), select, textarea')?.focus();
  }

  previous.addEventListener('click', () => show(current - 1, true));
  next.addEventListener('click', () => {
    const invalid = firstInvalid(panels[current]);
    if (invalid) {
      invalid.reportValidity();
      invalid.focus();
      return;
    }
    show(current + 1, true);
  });

  form.addEventListener('submit', (event) => {
    const invalidPanel = panels.findIndex((panel) => firstInvalid(panel));
    if (invalidPanel >= 0) {
      event.preventDefault();
      show(invalidPanel);
      const invalid = firstInvalid(panels[invalidPanel]);
      invalid?.reportValidity();
      invalid?.focus();
    }
  });

  const serverErrorPanel = panels.findIndex((panel) => panel.querySelector('.field-error'));
  show(serverErrorPanel >= 0 ? serverErrorPanel : 0);
})();
