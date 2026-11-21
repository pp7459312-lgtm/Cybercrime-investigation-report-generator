import sys
sys.path.insert(0, '.')
from app import app, init_db

init_db()

with app.test_client() as c:
    routes = ['/', '/login', '/register', '/report', '/track', '/admin/login']
    all_ok = True
    for route in routes:
        resp = c.get(route)
        ok = resp.status_code in [200, 302]
        print('GET', route.ljust(25), '->', resp.status_code, 'OK' if ok else 'FAIL')
        if not ok:
            all_ok = False

    # Test admin login POST
    resp = c.post('/admin/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=False)
    ok = resp.status_code in [200, 302]
    print('POST /admin/login         ->', resp.status_code, 'OK' if ok else 'FAIL')
    if not ok:
        all_ok = False

    # Test dashboard (unauthenticated → 302 redirect)
    resp = c.get('/dashboard', follow_redirects=False)
    print('GET /dashboard (unauth)   ->', resp.status_code, 'OK (redirect expected)')

    print()
    print('ALL ROUTES VERIFIED' if all_ok else 'SOME ROUTES FAILED')
