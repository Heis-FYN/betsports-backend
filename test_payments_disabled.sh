#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
rm -f /tmp/betsports-payments-test.db /tmp/betsports-payments-test.log /tmp/betsports-payments-cookie
PYTHON_BIN="${PYTHON_BIN:-/tmp/betsports-venv/bin/python}"
BETSPORTS_DB=/tmp/betsports-payments-test.db BETSPORTS_ADMIN_EMAIL=local-admin@example.com BETSPORTS_ADMIN_INITIAL_PASSWORD='local-admin-password' BETSPORTS_PAYMENTS_ENABLED=false "$PYTHON_BIN" app.py >/tmp/betsports-payments-test.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:5050/health >/dev/null && break; sleep 1; done
curl -fsS -c /tmp/betsports-payments-cookie -X POST http://127.0.0.1:5050/api/auth/register -H 'Content-Type: application/json' --data '{"name":"Payment Test User","email":"payment-test@example.com","password":"payment-test-password"}' >/tmp/payment-register.json
curl -sS -c /tmp/betsports-payments-cookie -b /tmp/betsports-payments-cookie -X POST http://127.0.0.1:5050/api/wallet/deposits -H 'Content-Type: application/json' --data '{"amount":100,"method":"mobile-money"}' -o /tmp/payment-deposit.json -w '%{http_code}' >/tmp/payment-deposit.status
curl -sS -c /tmp/betsports-payments-cookie -b /tmp/betsports-payments-cookie -X POST http://127.0.0.1:5050/api/wallet/withdrawals -H 'Content-Type: application/json' --data '{"amount":100,"method":"mobile-money"}' -o /tmp/payment-withdrawal.json -w '%{http_code}' >/tmp/payment-withdrawal.status
python3 - <<'PY'
import json
for label, status_path, body_path in [('deposit','/tmp/payment-deposit.status','/tmp/payment-deposit.json'),('withdrawal','/tmp/payment-withdrawal.status','/tmp/payment-withdrawal.json')]:
    status=open(status_path).read().strip()
    body=json.load(open(body_path))
    assert status == '503', (label, status, body)
    assert body.get('error',{}).get('code') == 'payment_gateway_disabled', (label, body)
    print(label, 'blocked', status, body['error']['code'])
PY
