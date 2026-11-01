"""HTTPS readiness/auth boundary and exact static lab release; no credentials."""
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

from cka_lab_private_api import ApiError, HOST, ORIGIN, NoRedirect, release, decode


def request(url, *, body=None, origin=None):
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    headers = {'User-Agent': 'ShadowOps-CKA-Lab-Release/1', 'Cache-Control': 'no-cache'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if origin:
        headers['Origin'] = origin
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, response.read(1048577), response.headers
    except urllib.error.HTTPError as error:
        # Never echo a response body; in particular Cloudflare challenges/URLs.
        result = error.code, b'', error.headers
        error.close()
        return result


def verify_api(pin):
    release(pin)
    status, raw, headers = request('https://' + HOST + '/api/labs/release')
    expected = {'application': 'cka-exam-simulator', 'build': pin['source_sha'], 'mode': 'restricted-lab-pilot'}
    if status != 200 or len(raw) > 4096 or json.loads(raw) != expected or headers.get('Cache-Control') != 'no-store':
        raise ApiError('Exact public lab controller release required')
    status, raw, _ = request('https://' + HOST + '/readyz')
    if status != 200 or len(raw) > 4096 or json.loads(raw) != {'status': 'ok'}:
        raise ApiError('Public lab controller is not ready')
    status, _, headers = request('https://' + HOST + '/api/labs/capabilities', body=b'{}', origin=ORIGIN)
    if (status != 401 or headers.get('Access-Control-Allow-Origin') != ORIGIN
            or headers.get('Cache-Control') != 'no-store' or headers.get('Set-Cookie')):
        raise ApiError('Public authenticated lab boundary did not verify')


def wait_api(pin, *, seconds=900):
    deadline = time.monotonic() + seconds
    print('CKA_LAB_WAITING_FOR_OPERATOR_TUNNEL_START', flush=True)
    while True:
        try:
            verify_api(pin)
            print('CKA_LAB_PUBLIC_API_VERIFIED authenticated_candidate_acceptance=false', flush=True)
            return
        except (ApiError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise ApiError('Public controller did not converge') from None
        time.sleep(5)


def verify_pages(pin):
    verify_api(pin)
    status, raw, _ = request(ORIGIN + '/release.json')
    expected = {'application': 'cka-exam-simulator', 'build': pin['source_sha'], 'mode': 'restricted-lab-staging'}
    if status != 200 or len(raw) > 4096 or json.loads(raw) != expected:
        raise ApiError('Exact public lab browser release required')
    status, html, _ = request(ORIGIN + '/')
    if status != 200 or len(html) > 1048576 or b'CKA // LAB' not in html:
        raise ApiError('Public lab browser unavailable')
    print('CKA_LAB_BROWSER_RELEASE_VERIFIED candidate_acceptance_verified=false', flush=True)


def wait_pages(pin, *, seconds=300):
    deadline = time.monotonic() + seconds
    while True:
        try:
            verify_pages(pin)
            return
        except (ApiError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise ApiError('Public browser release did not converge') from None
        time.sleep(5)


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {'api', 'wait-api', 'pages'}:
            return 64
        pin = release(decode(Path('deploy/cka-lab-staging-release.json').read_bytes()))
        {'api': verify_api, 'wait-api': wait_api, 'pages': wait_pages}[sys.argv[1]](pin)
        return 0
    except Exception:
        print('CKA_LAB_PUBLIC_VERIFICATION_BLOCKED', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
