'use strict';
document.addEventListener('DOMContentLoaded',()=>{
 if(!document.body.classList.contains('authenticated'))return;
 const forms=Array.from(document.querySelectorAll('form.form[method="post"]'));
 if(!forms.length)return;
 const fingerprint=form=>JSON.stringify(Array.from(new FormData(form).entries()).filter(([key])=>key!=='csrf'&&key!=='revision').map(([key,value])=>[key,value instanceof File?(value.name?[value.name,value.size,value.lastModified]:null):value]));
 const initial=new Map(forms.map(form=>[form,fingerprint(form)]));
 let leaving=false,pending=null,trigger=null;
 const dirty=except=>forms.some(form=>form!==except&&fingerprint(form)!==initial.get(form));
 const formStage=document.querySelector('[data-form-stage]');
 if(formStage){
  const updateStage=()=>{formStage.textContent=dirty()?'Есть несохранённый ввод.':'Поля ещё не изменены; сохранение записывает черновик.';};
  document.addEventListener('input',updateStage);document.addEventListener('change',updateStage);updateStage();
 }
 const dialog=document.createElement('dialog');dialog.className='leave-dialog';dialog.setAttribute('aria-labelledby','leave-title');
 const title=document.createElement('h2');title.id='leave-title';title.textContent='Изменения не сохранены';
 const text=document.createElement('p');text.textContent='Если уйти, внесённые правки будут потеряны.';
 const actions=document.createElement('div');actions.className='actions';
 const stay=document.createElement('button');stay.type='button';stay.textContent='Остаться';
 const leave=document.createElement('button');leave.type='button';leave.className='secondary';leave.textContent='Уйти без сохранения';
 actions.append(stay,leave);dialog.append(title,text,actions);document.body.append(dialog);
 function cancel(){pending=null;dialog.close();trigger?.focus();}
 stay.addEventListener('click',cancel);dialog.addEventListener('cancel',()=>{pending=null;});
 leave.addEventListener('click',()=>{const action=pending;pending=null;leaving=true;dialog.close();action?.();});
 function confirm(action,source){pending=action;trigger=source;if(!dialog.open)dialog.showModal();stay.focus();}
 window.addEventListener('beforeunload',event=>{if(!leaving&&dirty()){event.preventDefault();event.returnValue='';}});
 window.addEventListener('pageshow',()=>{leaving=false;});
 document.addEventListener('click',event=>{
  if(leaving||event.defaultPrevented||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey||!dirty())return;
  const anchor=event.target.closest('a[href]');if(!anchor||anchor.hasAttribute('download')||(anchor.target&&anchor.target!=='_self'))return;
  const target=new URL(anchor.href,location.href);if(!['http:','https:'].includes(target.protocol))return;
  if(target.origin===location.origin&&target.pathname===location.pathname&&target.search===location.search&&target.hash)return;
  event.preventDefault();confirm(()=>location.assign(target.href),anchor);
 });
 document.addEventListener('submit',event=>{
  if(event.defaultPrevented||leaving)return;
  const form=event.target;
  if(dirty(form)){
   event.preventDefault();const submitter=event.submitter;
   confirm(()=>submitter?form.requestSubmit(submitter):form.requestSubmit(),submitter);
  }else leaving=true;
 });
});
