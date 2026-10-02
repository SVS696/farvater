import io,json,shutil,unittest,uuid
from werkzeug.security import generate_password_hash
from web import create_app
from candidate_remote import RemoteError
import test_system_backup as fixture
import test_web as base

@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'),'age CLI needed')
class BackupWebTests(unittest.TestCase):
 login=base.WebTests.login
 def setUp(self):
  self.fixture=fixture.SystemBackupTests();self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
  panel=self.fixture.panel;(panel/'auth.json').write_text(json.dumps({'username':'owner','password_hash':generate_password_hash('test-password'),'session_secret':'fixture-secret'}));(panel/'policy.json').write_text('{}')
  parent=self
  class Backend:
   def call(self,action,**fields):
    try:return parent.fixture.call(action,**fields)
    except ValueError as error:raise RemoteError(str(error)) from None
  self.app=create_app(panel,candidate=Backend());self.app.testing=True;self.client=self.app.test_client()
 def test_export_download_upload_preview_and_delete_over_authenticated_http(self):
  csrf=self.login();value=uuid.uuid4().hex
  self.assertEqual(self.client.post('/backups/create',data={'csrf':csrf,'id':value}).status_code,302)
  result=self.client.post('/backups/'+value+'/download',data={'csrf':csrf});data=result.data;result.close()
  self.assertEqual(result.status_code,200);self.assertEqual(result.headers['Cache-Control'],'no-store');self.assertIn('.tar.gz.age',result.headers['Content-Disposition']);self.assertNotIn(b'PRIVATE CONFIG',data)
  imported=uuid.uuid4().hex;key=self.fixture.identity.read_bytes()
  r=self.client.post('/backups/upload',data={'csrf':csrf,'id':imported,'archive':(io.BytesIO(data),'copy.age'),'identity':(io.BytesIO(key),'recovery.agekey')})
  self.assertEqual(r.status_code,302);html=self.client.get('/backups').text
  self.assertIn('Проверка завершена',html);self.assertNotIn(key.decode(),html);self.assertNotIn('PRIVATE CONFIG',html)
  self.assertEqual(self.client.post('/backups/'+imported+'/delete',data={'csrf':csrf}).status_code,302)
 def test_auth_csrf_and_malformed_upload_do_not_change_host(self):
  self.assertEqual(self.client.get('/backups').status_code,302)
  self.assertEqual(self.client.post('/backups/upload',data=b'x'*300000,content_type='application/octet-stream').status_code,302)
  csrf=self.login();self.assertEqual(self.client.post('/backups/create',data={'csrf':'wrong','id':uuid.uuid4().hex}).status_code,403)
  r=self.client.post('/backups/upload',data={'csrf':csrf,'id':uuid.uuid4().hex,'archive':(io.BytesIO(b'not encrypted'),'broken.age'),'identity':(io.BytesIO(self.fixture.identity.read_bytes()),'key')})
  self.assertEqual(r.status_code,302);self.assertEqual((self.fixture.host/'etc/vpn.conf').read_text(),'PRIVATE CONFIG')
 def test_backup_page_survives_broken_policy_and_existing_upload_is_not_deleted(self):
  csrf=self.login();(self.fixture.panel/'policy.json').write_text('{broken')
  self.assertEqual(self.client.get('/backups').status_code,200)
  value=uuid.uuid4().hex;path=self.fixture.panel/'backup-uploads'/(value+'.age');path.write_bytes(b'existing')
  r=self.client.post('/backups/upload',data={'csrf':csrf,'id':value,'archive':(io.BytesIO(b'replacement'),'copy.age'),'identity':(io.BytesIO(self.fixture.identity.read_bytes()),'key')})
  self.assertEqual(r.status_code,302);self.assertEqual(path.read_bytes(),b'existing')
 def test_account_preflight_is_visible_and_names_are_escaped(self):
  self.login();exported,_=self.fixture.export();imported,_=self.fixture.inspect(exported)
  p=self.fixture.root/'jobs'/imported/'state.json';s=json.loads(p.read_text())
  s['summary']['accounts']={'ready':False,'issues':[{'kind':'conflicting_user','name':'<script>owner</script>','uid':1000}]}
  p.write_text(json.dumps(s));html=self.client.get('/backups').text
  self.assertIn('нужна подготовка перед восстановлением',html);self.assertIn('&lt;script&gt;owner',html);self.assertNotIn('<script>owner',html)

if __name__=='__main__':unittest.main()
