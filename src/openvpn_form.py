"""OpenVPN editor/import assembly; never starts a VPN or reads a server file."""
import copy
from openvpn_profile import from_form,validate,form_view
from openvpn_format import COMPAT,compat_options,parse,render
from native_endpoints import validate_bootstrap


def finish(form,native,compat,identifier,policy):
 name=form.get('name','').strip();scope=form.get('scope','')
 if not name or len(name)>120 or any(ord(c)<32 for c in name):raise ValueError('Название: от 1 до 120 символов')
 if scope not in ('public','work','special'):raise ValueError('Выберите назначение OpenVPN')
 resolver=form.get('domain_resolver','')
 if resolver:
  if resolver not in policy['dns'] or policy['dns'][resolver].get('native',{}).get('type')=='fakeip':raise ValueError('Выберите обычный DNS для адреса VPN')
  native['domain_resolver']=resolver
 else:native.pop('domain_resolver',None)
 import ipaddress
 for server in native['servers']:
  try:ipaddress.ip_address(server['server'])
  except ValueError:
   if not resolver:raise ValueError('Имя VPN-сервера требует начальный DNS. Выберите его в форме')
 native['tag']=identifier
 result={'name':name,'scope':scope,'protocol':'OpenVPN','native':validate(native,ready=True),'openvpn_export_options':compat_options(compat)}
 # Every profile accepted by this editor must also have a lossless native export.
 render(result)
 check=copy.deepcopy(policy);check['exits'][identifier]=result;validate_bootstrap(check)
 return result


def saved(form,previous,identifier,policy):
 compatibility={}
 for key,(arity,kind) in COMPAT.items():
  raw=form.get('compat_'+key,'')
  if not arity:
   if raw=='on':compatibility[key]=True
  elif raw.strip():
   value=raw.strip()
   if kind=='verbosity':
    if not value.isascii() or not value.isdigit():raise ValueError('Уровень журнала обычного клиента: число от 0 до 11')
    value=int(value)
   compatibility[key]=value
 return finish(form,from_form(form,previous.get('native',{})),compatibility,identifier,policy)


def imported(form,raw,files,identifier,policy):
 result=parse(raw,files=files,username=form.get('import_username',''),password=form.get('import_password',''))
 return finish(form,result['native'],result['openvpn_export_options'],identifier,policy)
