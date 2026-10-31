#!/usr/bin/env python3
"""Mandatory public TLS/account-only proof, independent of the OCI command receipt."""
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from cka_account_contract import HOST, SHA, AccountError

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def verify(sha,*,read=None,pause=time.sleep,clock=time.monotonic):
    if not SHA.fullmatch(sha):raise AccountError('Invalid account public source')
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def request(path):
        try:
            with opener.open('https://'+HOST+path,timeout=6) as r:return r.status,r.read(4096)
        except urllib.error.HTTPError as error:return error.code,b''
    get=read or request;deadline=clock()+180
    while True:
        try:
            status,body=get('/api/account/release')
            if status!=200 or json.loads(body)!={'application':'cka-exam-simulator','build':sha,'mode':'account-only-staging'}:raise AccountError('Source not ready')
            if get('/readyz')[0]!=200 or get('/api/account/me')[0]!=401:raise AccountError('Account boundary not ready')
            for path in ['/api/dev/lab/start','/api/scenarios','/docs']:
                if get(path)[0]!=404:raise AccountError('Unexpected privileged route')
            return 'CKA_ACCOUNT_PUBLIC_SOURCE_OK '+sha
        except (AccountError,ValueError,urllib.error.URLError,OSError,TimeoutError):
            if clock()>=deadline:raise AccountError('Public account source did not verify') from None
            pause(5)
if __name__=='__main__':
    try:print(verify(sys.argv[1]))
    except Exception as error:print('CKA_ACCOUNT_VERIFY_BLOCKED type='+type(error).__name__);raise SystemExit(1)
