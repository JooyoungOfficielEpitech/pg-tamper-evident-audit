#!/usr/bin/env bash
# End-to-end demo: start Postgres, install the audit log, write concurrently,
# prove the WORM guard, then tamper as superuser and show verify() catching it.
set -euo pipefail

CONTAINER=pg-audit-demo
PORT=${PORT:-55432}
cd "$(dirname "$0")/.."

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" postgres:17 >/dev/null
until docker exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1; do sleep 0.5; done
sleep 1

su()  { docker exec -i "$CONTAINER" psql -U postgres -v ON_ERROR_STOP=1 -qAt "$@"; }
app() { docker exec -i -e PGPASSWORD=app "$CONTAINER" psql -h localhost -U app -d postgres -v ON_ERROR_STOP=1 -qAt "$@"; }

su < sql/01_audit.sql
su < sql/02_roles_and_capture.sql
echo "✔ schema installed"

# 1. Concurrent writers: 8 sessions x 25 changes each.
for w in $(seq 1 8); do
  (
    for i in $(seq 1 25); do
      echo "SET app.actor = 'worker-$w';
            INSERT INTO record(owner, body) VALUES ('w$w', '{\"i\": $i}');
            UPDATE record SET body = body || '{\"seen\": true}' WHERE id = (SELECT max(id) FROM record WHERE owner = 'w$w');"
    done | app >/dev/null
  ) &
done
wait
echo "✔ $(app -c 'SELECT count(*) FROM audit.event') audit events written by 8 concurrent sessions"
echo "✔ verify() after concurrent writes: $(app -c "SELECT coalesce((SELECT reason FROM audit.verify()), 'chain intact')")"

# 2. The application role cannot rewrite history.
if app -c "DELETE FROM audit.event WHERE id = 1" 2>/dev/null; then
  echo "✘ app was able to delete"; exit 1
else
  echo "✔ app role: DELETE on audit.event rejected"
fi

# 3. Even the table owner hits the WORM trigger.
if su -c "UPDATE audit.event SET actor = 'mallory' WHERE id = 10" 2>/dev/null; then
  echo "✘ owner was able to update"; exit 1
else
  echo "✔ owner: UPDATE on audit.event blocked by WORM trigger"
fi

# 4. A superuser can disable triggers. The hash chain still exposes the edit.
su -c "ALTER TABLE audit.event DISABLE TRIGGER event_no_update;
       UPDATE audit.event SET actor = 'mallory' WHERE id = 42;
       ALTER TABLE audit.event ENABLE TRIGGER event_no_update;"
echo "✔ superuser silently edited row 42 -> verify(): $(su -c "SELECT broken_at || ' / ' || reason FROM audit.verify()")"
