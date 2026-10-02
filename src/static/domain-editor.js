'use strict';
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-domain-editor]').forEach(editor => {
    const q = name => editor.querySelector('[data-' + name + ']');
    const raw = q('domain-text'), list = q('domain-list'), search = q('domain-search');
    const dialog = q('domain-dialog'), name = q('domain-name'), exact = q('domain-exact'), suffix = q('domain-suffix');
    const target = q('domain-target'), error = q('domain-error'), groupDialog = q('group-dialog');
    let editing = null;
    const savedText=raw.value;
    const opened = new Set(), openedDomains = new Set();
    const node = (tag, text, cls) => {const e = document.createElement(tag); if(text !== undefined)e.textContent=text; if(cls)e.className=cls; return e;};
    function button(text, action) {const b=node('button',text,'secondary small');b.type='button';b.addEventListener('click',action);return b;}
    function canonical(value) {
      value=value.trim().toLowerCase().replace(/\.$/,'');
      if(!value || /[\s/:@?#*\\]/.test(value))throw new Error('Введите домен без протокола, пути, порта и маски.');
      const result=new URL('https://' + value).hostname;
      if(result.length>253 || !result.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)))throw new Error('Некорректное имя домена.');
      return result;
    }
    function read(tolerant=false) {
      const groups=[{title:'',entries:[]}];groups.problems=[];
      raw.value.split(/\r?\n/).forEach((line,index)=>{
        line=line.trim();if(!line)return;
        try {
          if(line.startsWith('#')){
            const title=line.slice(1).trim();
            if(!title||title.length>160)throw new Error('После # нужно название группы до 160 символов.');
            groups.push({title,entries:[]});return;
          }
          const wildcard=line.startsWith('*.');
          groups[groups.length-1].entries.push((wildcard?'*.':'')+canonical(wildcard?line.slice(2):line));
        }catch(error){
          const message='Строка '+(index+1)+': '+error.message;
          if(!tolerant)throw new Error(message);
          groups.problems.push(message);
        }
      });
      return groups;
    }
    function write(groups) {
      raw.value=groups.map(g=>(g.title?'# '+g.title+'\n':'')+g.entries.join('\n')).join('\n\n').trim();
      raw.dispatchEvent(new Event('input',{bubbles:true}));
    }
    function patterns(groups) {return groups.flatMap(g=>g.entries);}
    function covered(domain,entries) {return entries.filter(p=>p.startsWith('*.') && domain.endsWith('.'+p.slice(2)));}
    function unsaved() {return raw.value===savedText?'':'Изменения не сохранены.';}
    function render() {
      list.replaceChildren();
      const groups=read(true);
      raw.setCustomValidity(groups.problems[0]||'');
      const all=patterns(groups), term=search.value.trim().toLowerCase();
      let count=0;
      groups.forEach((g,index)=>{
        if(!g.title && !g.entries.length)return;
        const section=node('details',undefined,'domain-group');section.dataset.groupIndex=index;
        section.open=opened.has(index)||Boolean(term);
        section.append(node('summary',(g.title||'Без группы')+' · '+g.entries.length+' условий'));
        section.addEventListener('toggle',()=>{if(!section.isConnected)return;if(section.open)opened.add(index);else opened.delete(index);});
        const actions=node('div',undefined,'actions');actions.append(button('Добавить сайт',()=>open(null,index)));
        section.append(actions);
        // Group only explicit parent names. Never guess registrable domains (co.uk, etc.).
        const bases=[...new Set(g.entries.map(p=>p.replace(/^\*\./,'')))];
        const roots=bases.filter(b=>!bases.some(parent=>parent!==b && b.endsWith('.'+parent)));
        roots.forEach(base=>{
          const members=bases.filter(b=>b===base||b.endsWith('.'+base));
          if(term && !g.title.toLowerCase().includes(term) && !members.some(b=>b.includes(term)))return;
          count++;
          const item=node('details',undefined,'domain-item'),itemKey=index+':'+base;item.open=Boolean(term)||openedDomains.has(itemKey);
          item.addEventListener('toggle',()=>{if(!item.isConnected)return;if(item.open)openedDomains.add(itemKey);else openedDomains.delete(itemKey);});
          item.append(node('summary',base+(members.length>1?' · '+(members.length-1)+' отдельных поддоменов':'')));
          const rows=node('div',undefined,'domain-members');
          members.forEach(domain=>{
            const row=node('div',undefined,'domain-entry');
            const info=node('div');info.append(node('strong',domain));
            const states=[];
            if(g.entries.includes(domain))states.push('сам домен');
            if(g.entries.includes('*.'+domain))states.push('все поддомены');
            info.append(node('p',states.join(' + '),'muted'));
            const masks=covered(domain,all);if(masks.length)info.append(node('p','Уже покрыт: '+masks.join(', '),'muted'));
            const controls=node('div',undefined,'actions');
            controls.append(button('Настроить',()=>open(domain,index)),button('Удалить',()=>open(domain,index,true)));
            row.append(info,controls);rows.append(row);
          });
          item.append(rows,button('Добавить поддомен',()=>open(null,index,false,base)));section.append(item);
        });
        if(!term || section.querySelector('.domain-item') || g.title.toLowerCase().includes(term))list.append(section);
      });
      q('domain-status').textContent=(term?'Найдено групп доменов: '+count:all.length+' доменных условий.')+' '+(groups.problems.length?groups.problems[0]+' Остальные строки показаны. ':'')+unsaved();
    }
    function preview() {
      let domain;try{domain=canonical(name.value);}catch(_){domain=name.value.trim();}
      q('domain-exact-name').textContent=domain;
      q('domain-suffix-name').textContent=domain?'*.'+domain:'';
      try {const masks=covered(domain,patterns(read()));q('domain-coverage').textContent=masks.length?'Имя уже покрыто: '+masks.join(', '):'';}catch(_){/* Raw editor reports its own error. */}
    }
    function open(domain,index=0,removing=false,parent='') {
      let groups;try{groups=read();}catch(_){render();return;}
      editing=domain?{domain,index}:null;
      target.replaceChildren();groups.forEach((g,i)=>{const option=node('option',g.title||'Без группы');option.value=i;target.append(option);});
      target.value=index;target.disabled=Boolean(editing);
      name.value=domain||'';name.disabled=Boolean(editing);name.placeholder=parent?'sub.'+parent:'example.com';
      exact.checked=domain?groups[index].entries.includes(domain):true;
      suffix.checked=domain?groups[index].entries.includes('*.'+domain):true;
      editor.querySelector('#domain-dialog-title').textContent=removing?'Удалить условия сайта':domain?'Настроить сайт':parent?'Добавить поддомен':'Добавить сайт';
      q('domain-save').textContent=domain?'Сохранить выбор':'Добавить';q('domain-save').hidden=removing;
      q('domain-delete').hidden=!removing;error.hidden=true;preview();dialog.showModal();
      (domain?exact:name).focus();
    }
    function save(removing=false) {
      try {
        const domain=canonical(name.value),groups=read(),index=Number(target.value),g=groups[index];
        if(!g)throw new Error('Выберите группу.');
        if(!exact.checked&&!suffix.checked)throw new Error('Выберите сам домен или поддомены.');
        const selected=[...(exact.checked?[domain]:[]),...(suffix.checked?['*.'+domain]:[])];
        if(editing && !removing)g.entries=g.entries.filter(p=>p!==domain && p!=='*.'+domain);
        if(removing)g.entries=g.entries.filter(p=>!selected.includes(p));
        else selected.forEach(p=>{if(!g.entries.includes(p))g.entries.push(p);});
        opened.add(index);write(groups);dialog.close();
      }catch(e){error.textContent=e.message;error.hidden=false;}
    }
    q('domain-add').addEventListener('click',()=>open(null));
    q('domain-save').addEventListener('click',()=>save());q('domain-delete').addEventListener('click',()=>save(true));
    q('domain-cancel').addEventListener('click',()=>dialog.close());name.addEventListener('input',preview);
    // Enter in a dialog must never submit the enclosing rule form.
    [dialog,groupDialog].forEach(d=>d.addEventListener('keydown',event=>{if(event.key==='Enter' && event.target.tagName==='INPUT'){event.preventDefault();if(d===dialog)save(!q('domain-delete').hidden);else q('group-save').click();}}));
    search.addEventListener('keydown',e=>{if(e.key==='Enter')e.preventDefault();});
    search.addEventListener('input',render);raw.addEventListener('input',render);
    q('domain-expand').addEventListener('click',()=>list.querySelectorAll('details').forEach(d=>d.open=true));
    q('domain-collapse').addEventListener('click',()=>list.querySelectorAll('details').forEach(d=>d.open=false));
    q('domain-group-add').addEventListener('click',()=>{q('group-name').value='';q('group-error').textContent='';groupDialog.showModal();q('group-name').focus();});
    q('group-cancel').addEventListener('click',()=>groupDialog.close());
    q('group-save').addEventListener('click',()=>{
      const title=q('group-name').value.trim();if(!title||/[\r\n]/.test(title)){q('group-error').textContent='Введите название группы.';return;}
      try {const groups=read();groups.push({title,entries:[]});opened.add(groups.length-1);write(groups);groupDialog.close();}catch(_){groupDialog.close();render();}
    });
    q('domain-tools').hidden=false;editor.querySelector('.domain-raw').open=false;render();
  });
});
