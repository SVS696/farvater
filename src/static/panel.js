'use strict';
// UI preferences contain no credentials or network settings.
function setTheme(value) {
  document.documentElement.dataset.theme = ['light', 'dark'].includes(value) ? value : 'system';
}
try { setTheme(localStorage.getItem('network-panel-theme')); } catch (_) { setTheme('system'); }
document.addEventListener('DOMContentLoaded', () => {
  const theme = document.querySelector('#theme-choice');
  if (theme) {
    theme.value = document.documentElement.dataset.theme;
    theme.addEventListener('change', () => {
      setTheme(theme.value);
      try { localStorage.setItem('network-panel-theme', theme.value); } catch (_) { /* Private browsing remains usable. */ }
    });
  }
  document.querySelectorAll('[data-client-export]').forEach(form => {
    let imageUrl = null;
    const output = form.querySelector('[data-qr-output]');
    const trigger = form.querySelector('[value="qr"]');
    function clearQR() {
      output.replaceChildren();
      if (imageUrl) URL.revokeObjectURL(imageUrl);
      imageUrl = null;
      trigger.textContent = 'Показать QR';
      trigger.setAttribute('aria-expanded', 'false');
    }
    form.addEventListener('submit', async event => {
      if (event.submitter !== trigger) return;
      event.preventDefault();
      if (imageUrl) { clearQR(); return; }
      trigger.disabled = true;
      trigger.textContent = 'Создаём QR…';
      output.textContent = '';
      try {
        const data = new FormData(form);
        data.set('format', 'qr');
        const response = await fetch(form.action, {method: 'POST', body: data, credentials: 'same-origin', cache: 'no-store'});
        if (response.redirected) throw new Error('Сессия завершилась. Войдите в панель снова.');
        if (!response.ok || !response.headers.get('Content-Type')?.includes('image/svg+xml'))
          throw new Error(response.status === 409 ? 'Настройки изменились. Обновите страницу и повторите.' : 'Не удалось показать QR. Повторите запрос или скачайте конфиг.');
        imageUrl = URL.createObjectURL(await response.blob());
        const image = document.createElement('img');
        image.alt = 'QR подключения: ' + form.dataset.clientExport;
        image.width = 240; image.height = 240; image.src = imageUrl;
        output.replaceChildren(image);
        trigger.textContent = 'Скрыть QR';
        trigger.setAttribute('aria-expanded', 'true');
      } catch (error) { clearQR(); output.textContent = error.message; }
      finally { trigger.disabled = false; }
    });
    window.addEventListener('pagehide', clearQR);
  });
});

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-reserve-editor]').forEach(editor => {
    const list = editor.querySelector('[data-reserve-list]');
    const add = editor.querySelector('[data-reserve-add]');
    const status = editor.querySelector('[data-reserve-status]');
    const rows = () => Array.from(list.querySelectorAll('[data-reserve-row]'));
    function refresh(message = '') {
      const items = rows();
      items.forEach((row, index) => {
        const title = 'Резерв ' + (index + 1);
        row.querySelector('[data-reserve-title]').textContent = title;
        const up = row.querySelector('[data-reserve-up]');
        const down = row.querySelector('[data-reserve-down]');
        up.disabled = index === 0; down.disabled = index === items.length - 1;
        up.setAttribute('aria-label', title + ': выше');
        down.setAttribute('aria-label', title + ': ниже');
        row.querySelector('[data-reserve-remove]').setAttribute('aria-label', title + ': удалить');
        const fields = Array.from(row.querySelectorAll('select'));
        fields.forEach(field => { field.required = fields.some(item => item.value !== ''); });
      });
      add.disabled = items.length >= 31;
      status.textContent = message || (items.length === 0 ? 'Резервов нет. Используется только основной выход.' : '');
    }
    add.addEventListener('click', () => {
      if (rows().length >= 31) return;
      list.append(editor.querySelector('[data-reserve-template]').content.cloneNode(true));
      refresh('Добавлен резерв ' + rows().length + '. Выберите выход и DNS.');
      rows().at(-1).querySelector('select').focus();
    });
    list.addEventListener('change', () => refresh());
    list.addEventListener('click', event => {
      const button = event.target.closest('button');
      const row = button?.closest('[data-reserve-row]');
      if (!row) return;
      if (button.hasAttribute('data-reserve-remove')) {
        const next = row.nextElementSibling || row.previousElementSibling;
        row.remove(); refresh(rows().length ? 'Резерв удалён из формы.' : '');
        (next?.querySelector('select') || add).focus();
      } else if (button.hasAttribute('data-reserve-up') && row.previousElementSibling) {
        list.insertBefore(row, row.previousElementSibling); refresh('Резерв перемещён выше.');
        row.querySelector('select').focus();
      } else if (button.hasAttribute('data-reserve-down') && row.nextElementSibling) {
        list.insertBefore(row.nextElementSibling, row); refresh('Резерв перемещён ниже.');
        row.querySelector('select').focus();
      }
    });
    enableDragOrder(list, '[data-reserve-row]', () => refresh('Порядок резервов изменён в форме.'));
    refresh();
  });
  const ruleList = document.querySelector('[data-rule-order]');
  if (ruleList) enableDragOrder(ruleList, '[data-rule-id]', () => {
    const form = document.querySelector('#rule-order-form');
    form.querySelectorAll('[name=order]').forEach(input => input.remove());
    ruleList.querySelectorAll('[data-rule-id]').forEach(row => {
      const input = document.createElement('input');
      input.type = 'hidden'; input.name = 'order'; input.value = row.dataset.ruleId; form.append(input);
    });
    form.requestSubmit();
  });
});

// Drag only from the handle; selecting text and using form fields remain normal.
function enableDragOrder(list, selector, changed) {
  let dragged = null;
  list.addEventListener('dragstart', event => {
    const handle = event.target.closest('[data-drag-handle]');
    dragged = handle?.closest(selector) || null;
    if (!dragged) { event.preventDefault(); return; }
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', 'panel-row');
    dragged.classList.add('dragging');
  });
  list.addEventListener('dragover', event => {
    const target = event.target.closest(selector);
    if (!dragged || !target || target === dragged || target.parentElement !== dragged.parentElement) return;
    event.preventDefault(); event.dataTransfer.dropEffect = 'move';
  });
  list.addEventListener('drop', event => {
    const target = event.target.closest(selector);
    if (!dragged || !target || target === dragged || target.parentElement !== dragged.parentElement) return;
    event.preventDefault();
    const items = Array.from(dragged.parentElement.children);
    target.parentElement.insertBefore(dragged, items.indexOf(dragged) < items.indexOf(target) ? target.nextSibling : target);
    dragged.classList.remove('dragging'); dragged = null; changed();
  });
  list.addEventListener('dragend', () => { dragged?.classList.remove('dragging'); dragged = null; });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-filter-lists]').forEach(editor => {
    const list = editor.querySelector('[data-filter-list]');
    const add = editor.querySelector('[data-filter-add]');
    const status = editor.querySelector('[data-filter-status]');
    const rows = () => Array.from(list.querySelectorAll('[data-filter-row]'));
    const heading = editor.querySelector('h2').textContent;
    function refresh(message = '') {
      rows().forEach((row, i) => {
        row.querySelector('[data-filter-title]').textContent = heading + ' · ' + (i + 1);
        row.querySelector('[data-filter-remove]').setAttribute('aria-label', 'Удалить список ' + (i + 1));
      });
      add.disabled = rows().length >= 32;
      status.textContent = message || (rows().length ? '' : 'Списков нет.');
    }
    add.addEventListener('click', () => {
      if (rows().length >= 32) return;
      list.append(editor.querySelector('[data-filter-template]').content.cloneNode(true));
      refresh('Добавлен список. Укажите название и URL.');
      rows().at(-1).querySelector('input').focus();
    });
    list.addEventListener('click', event => {
      const button = event.target.closest('[data-filter-remove]');
      if (!button) return;
      const row = button.closest('[data-filter-row]');
      const next = row.nextElementSibling || row.previousElementSibling;
      row.remove(); refresh(rows().length ? 'Список удалён из формы. Сохраните настройки.' : '');
      (next?.querySelector('input') || add).focus();
    });
    refresh();
  });
});

document.addEventListener('DOMContentLoaded', () => {
  function openLinkedSection() {
    if (location.hash === '#rule-automation') {
      const section = document.querySelector('#rule-automation');
      if (section) section.open = true;
    }
  }
  openLinkedSection(); window.addEventListener('hashchange', openLinkedSection);
});

document.addEventListener('DOMContentLoaded',()=>{
 document.querySelectorAll('[data-server-access]').forEach(form=>{
  const list=form.querySelector('[data-server-targets]'),add=form.querySelector('[data-server-target-add]');let dragging=null;
  const rows=()=>Array.from(list.querySelectorAll('[data-server-target]'));
  function refresh(){const all=rows();all.forEach((r,i)=>{r.querySelector('legend').textContent=i?'Резервный адрес '+i:'Основной адрес';r.querySelector('[data-server-target-up]').disabled=i===0;r.querySelector('[data-server-target-down]').disabled=i===all.length-1;r.querySelector('[data-server-target-remove]').disabled=all.length===1;});add.disabled=all.length>=8;}
  add.addEventListener('click',()=>{if(rows().length<8){list.append(form.querySelector('template').content.cloneNode(true));refresh();}});
  list.addEventListener('click',e=>{const r=e.target.closest('[data-server-target]');if(!r)return;if(e.target.closest('[data-server-target-remove]')&&rows().length>1)r.remove();if(e.target.closest('[data-server-target-up]')&&r.previousElementSibling)list.insertBefore(r,r.previousElementSibling);if(e.target.closest('[data-server-target-down]')&&r.nextElementSibling)list.insertBefore(r.nextElementSibling,r);refresh();});
  list.addEventListener('dragstart',e=>{if(!e.target.closest('[data-server-target-drag]'))return;dragging=e.target.closest('[data-server-target]');e.dataTransfer.setData('text/plain','server-target');e.dataTransfer.effectAllowed='move';});
  list.addEventListener('dragover',e=>{if(dragging)e.preventDefault();});list.addEventListener('drop',e=>{if(!dragging)return;e.preventDefault();const row=e.target.closest('[data-server-target]');if(row&&row!==dragging)list.insertBefore(dragging,e.clientY>row.getBoundingClientRect().top+row.clientHeight/2?row.nextSibling:row);dragging=null;refresh();});list.addEventListener('dragend',()=>dragging=null);refresh();
 });
});

document.addEventListener('DOMContentLoaded', () => {
  const editor=document.querySelector('[data-monitor-editor]');
  const choice=editor?.querySelector('[data-monitor-kind]');
  choice?.addEventListener('change',()=>{
    const previous=editor.querySelector('[data-monitor-fields]:not([hidden])');
    const shared={};['name','scope','action'].forEach(key=>shared[key]=previous?.querySelector(`[name="${key}"]`)?.value);
    editor.querySelectorAll('[data-monitor-fields]').forEach(fields=>{
      const active=fields.dataset.monitorFields===choice.value;
      fields.hidden=!active;fields.disabled=!active;
      if(active)Object.entries(shared).forEach(([key,value])=>{if(value!==undefined)fields.querySelector(`[name="${key}"]`).value=value;});
    });
  });
  const form=document.querySelector('[data-monitor-layout]'),list=form?.querySelector('[data-monitor-order]');
  if(list){
    const refresh=()=>{
      const rows=Array.from(list.children);
      rows.forEach((row,i)=>{row.querySelector('[data-monitor-move="up"]').disabled=i===0;row.querySelector('[data-monitor-move="down"]').disabled=i===rows.length-1;});
    };
    const changed=()=>{refresh();form.querySelector('[data-monitor-layout-status]').textContent='Изменения не сохранены';form.dispatchEvent(new Event('input',{bubbles:true}));};
    enableDragOrder(list,'[data-monitor-row]',changed);
    list.addEventListener('click',event=>{
      const button=event.target.closest('[data-monitor-move]');if(!button)return;
      const row=button.closest('[data-monitor-row]'),next=button.dataset.monitorMove==='up'?row.previousElementSibling:row.nextElementSibling;
      if(next){list.insertBefore(row,button.dataset.monitorMove==='up'?next:next.nextSibling);changed();}
    });
    list.addEventListener('change',changed);refresh();
  }
});

// Progressive enhancement: navigation and filtering remain usable without JS.
document.documentElement.classList.add('js');
document.addEventListener('DOMContentLoaded',()=>{
  const menu=document.querySelector('.menu-toggle'), nav=document.getElementById('panel-navigation');
  if(menu&&nav)menu.addEventListener('click',()=>{const open=nav.classList.toggle('is-open');menu.setAttribute('aria-expanded',String(open));menu.textContent=open?'Закрыть меню':'Меню';});
  document.querySelectorAll('[data-list-search]').forEach(input=>{
    const list=document.getElementById(input.dataset.listSearch);if(!list)return;
    input.addEventListener('input',()=>{const query=input.value.trim().toLocaleLowerCase('ru');let found=0;list.querySelectorAll('[data-search-row]').forEach(row=>{row.hidden=!row.textContent.toLocaleLowerCase('ru').includes(query);if(!row.hidden)found++;});const empty=list.querySelector('[data-search-empty]');if(empty)empty.hidden=found>0||!query;});
  });
  document.addEventListener('invalid',event=>{let parent=event.target.parentElement;while(parent){if(parent.tagName==='DETAILS')parent.open=true;parent=parent.parentElement;}},true);
});

// Peer editing is local until the existing save/apply flow is used.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-peer-editor]').forEach(form => {
    const list = form.querySelector('[data-wg-peers]');
    const add = form.querySelector('[data-peer-add]');
    const count = form.elements.peer_count;
    const status = form.querySelector('[data-peer-status]');
    const refresh = (message = '') => {
      const rows = Array.from(list.children);
      count.value = rows.length;
      rows.forEach((row, index) => {
        row.querySelector('[data-peer-title]').textContent = 'Пир ' + (index + 1);
        row.querySelector('[data-peer-remove]').setAttribute('aria-label', 'Удалить пира ' + (index + 1));
        row.querySelectorAll('[name]').forEach(input => {
          input.name = input.name.replace(/^peer_(?:[0-9]+|__INDEX__)_/, 'peer_' + index + '_');
        });
      });
      add.disabled = rows.length >= 64;
      status.textContent = message || (rows.length ? '' : 'Пиров пока нет. Нажмите «Добавить пира».');
    };
    add.addEventListener('click', () => {
      if (list.children.length >= 64) return;
      const row = form.querySelector('[data-peer-template]').content.firstElementChild.cloneNode(true);
      row.dataset.newPeer = 'true';
      list.append(row);
      refresh('Изменения не сохранены');
      row.querySelector('[name$="_PublicKey"]').focus();
    });
    list.addEventListener('click', event => {
      const button = event.target.closest('[data-peer-remove], [data-peer-undo]');
      if (!button) return;
      const row = button.closest('[data-wg-peer]');
      const removed = button.hasAttribute('data-peer-remove');
      // New entries have no server-side identity and can be discarded outright.
      if (removed && row.dataset.newPeer) {
        row.remove(); refresh('Изменения не сохранены'); add.focus(); return;
      }
      row.querySelector('[data-peer-removed]').value = removed ? 'on' : '';
      row.querySelector('[data-peer-fields]').hidden = removed;
      row.querySelector('[data-peer-fields]').disabled = removed;
      row.querySelector('[data-peer-notice]').hidden = !removed;
      row.querySelector('[data-peer-remove]').hidden = removed;
      refresh('Изменения не сохранены');
      row.querySelector(removed ? '[data-peer-undo]' : '[data-peer-remove]').focus();
    });
    refresh();
  });
});


document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-incoming-editor]').forEach(form => {
    const list = form.querySelector('[data-incoming-clients]');
    const add = form.querySelector('[data-incoming-client-add]');
    const refresh = () => { add.disabled = list.children.length >= 64; };
    add.addEventListener('click', () => {
      if (list.children.length >= 64) return;
      const row = form.querySelector('[data-incoming-client-template]').content.firstElementChild.cloneNode(true);
      list.append(row); row.querySelector('[name="client_name"]').focus(); refresh();
      form.dispatchEvent(new Event('input', {bubbles:true}));
    });
    list.addEventListener('click', event => {
      const button = event.target.closest('[data-incoming-client-remove]');
      if (!button) return;
      button.closest('[data-incoming-client]').remove(); refresh();
      form.dispatchEvent(new Event('input', {bubbles:true}));
    });
    refresh();
  });
});
