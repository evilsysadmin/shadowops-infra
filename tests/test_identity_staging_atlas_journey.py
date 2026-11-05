import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import identity_staging_atlas_journey as journey

PORT=12345
NETWORK='shadowops-identity-atlas-canary-net-'+'c'*24
NONCE='a'*16
SUBJECT='11111111-1111-4111-8111-111111111111'
URI='mongodb+srv://inventory:synthetic-password-12345@cluster.mongodb.net/shadowops_identity_staging?authSource=admin&tls=true'
CONFIG={'admin_inventory_mongo_uri':URI}
COOKIE=journey.COOKIE+'=synthetic-cookie; Path=/; Secure; HttpOnly'

class JourneyTests(unittest.TestCase):
 def test_register_promote_admin_and_remove_only_synthetic_account(self):
  calls=[]
  def http(port,ca,path,payload,cookie=None):
   calls.append(('http',path,cookie))
   if path.endswith('/register'):return 201,''
   if path.endswith('/login'):return 204,COOKIE
   calls_before=[c for c in calls if c[:2]==('http','/api/identity/admin/accounts')]
   return (401 if len(calls_before)==1 else 200),''
  def mongo(uri,network,name,op,subject=None):
   calls.append(('mongo',name,op,subject))
   return SUBJECT if op=='lookup' else None
  self.assertEqual(journey.perform(PORT,NETWORK,'ca',CONFIG,http=http,mongo=mongo,nonce=NONCE),'IDENTITY_ATLAS_ADMIN_JOURNEY_OK')
  actions=[x[2] for x in calls if x[0]=='mongo']
  self.assertEqual(actions,['lookup','promote','cleanup'])
  self.assertTrue(all(x[1]=='identitycanary_'+NONCE for x in calls if x[0]=='mongo'))
  self.assertEqual(calls[-1][3],SUBJECT)
 def test_failure_after_registration_still_cleans_and_cleanup_failure_fails_closed(self):
  for fail_cleanup in (False,True):
   actions=[]
   def http(port,ca,path,payload,cookie=None):
    return (201,'') if path.endswith('/register') else (403,'')
   def mongo(uri,network,name,op,subject=None):
    actions.append(op)
    if op=='lookup':return SUBJECT
    if op=='cleanup' and fail_cleanup:raise journey.JourneyError('cleanup')
   with self.assertRaises(journey.JourneyError):journey.perform(PORT,NETWORK,'ca',CONFIG,http=http,mongo=mongo,nonce=NONCE)
   self.assertEqual(actions,['lookup','cleanup'])
 def test_ambiguous_registration_reports_only_synthetic_name(self):
  import contextlib,io
  stderr=io.StringIO();calls=[]
  def http(*args,**kwargs):raise journey.JourneyError('network')
  def mongo(*args,**kwargs):calls.append(args)
  with contextlib.redirect_stderr(stderr),self.assertRaises(journey.JourneyError):
   journey.perform(PORT,NETWORK,'ca',CONFIG,http=http,mongo=mongo,nonce=NONCE)
  self.assertIn('IDENTITY_ATLAS_CANARY_REGISTRATION_UNCERTAIN name=identitycanary_'+NONCE,stderr.getvalue())
  self.assertNotIn(URI,stderr.getvalue());self.assertEqual(calls,[])

 def test_unrelated_identity_or_network_is_denied_before_docker(self):
  calls=[]
  def runner(*args,**kwargs):calls.append(args);return SimpleNamespace(returncode=0,stdout='')
  for net,name,op,subject in [(NETWORK,'evilsysadmin','cleanup',SUBJECT),('wrong','identitycanary_'+NONCE,'lookup',None),(NETWORK,'identitycanary_'+NONCE,'promote','bad')]:
   with self.assertRaises(journey.JourneyError):journey.mongo_action(URI,net,name,op,subject,runner=runner)
  self.assertEqual(calls,[])
 def test_mongo_receipts_are_bounded_and_secrets_only_in_stdin(self):
  seen=[]
  def runner(args,**kwargs):
   seen.append((args,kwargs));return SimpleNamespace(returncode=0,stdout='CANARY_SUBJECT:'+SUBJECT+'\n')
  self.assertEqual(journey.mongo_action(URI,NETWORK,'identitycanary_'+NONCE,'lookup',runner=runner),SUBJECT)
  args,kw=seen[0]
  self.assertNotIn(URI,' '.join(args))
  self.assertIn(URI,kw['input'])
  self.assertNotIn('password',str(args))

class LoopbackTLSTests(unittest.TestCase):
 def test_request_verifies_hostname_and_reaches_only_loopback(self):
  import http.server
  import ssl
  import subprocess
  import tempfile
  import threading
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_POST(self):
    self.server.observed=(self.headers.get('Host'),self.headers.get('Origin'),self.rfile.read(int(self.headers['Content-Length'])))
    self.send_response(204);self.send_header('Set-Cookie',COOKIE);self.end_headers()
   def log_message(self,*args):pass
  with tempfile.TemporaryDirectory() as temp:
   cert=Path(temp)/'cert.pem';key=Path(temp)/'key.pem'
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+journey.HOST,'-addext','subjectAltName=DNS:'+journey.HOST,'-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
   server=http.server.HTTPServer(('127.0.0.1',0),Handler)
   context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);server.socket=context.wrap_socket(server.socket,server_side=True)
   thread=threading.Thread(target=server.handle_request);thread.start()
   try:
    status,cookie=journey.request(server.server_port,cert,'/fixture',{'example':'fixture'})
    self.assertEqual(status,204);self.assertIn(journey.COOKIE,cookie)
    self.assertEqual(server.observed[0],journey.HOST);self.assertEqual(server.observed[1],journey.ORIGIN)
    self.assertEqual(json.loads(server.observed[2]),{'example':'fixture'})
   finally:
    thread.join(timeout=10);server.server_close()
