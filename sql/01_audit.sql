-- Tamper-evident audit log for PostgreSQL
-- 1) append-only (WORM) table  2) SHA-256 hash chain  3) serialized appends  4) verification

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.event (
    id           bigint      PRIMARY KEY,
    occurred_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor        text        NOT NULL,
    action       text        NOT NULL CHECK (action IN ('INSERT','UPDATE','DELETE','READ')),
    entity       text        NOT NULL,
    entity_id    text        NOT NULL,
    before_state jsonb,
    after_state  jsonb,
    prev_hash    bytea       NOT NULL,
    hash         bytea       NOT NULL UNIQUE
);
CREATE SEQUENCE audit.event_id_seq OWNED BY audit.event.id;

-- Canonical representation that gets hashed. jsonb normalises key order, so the text is stable.
CREATE FUNCTION audit.canonical(e audit.event) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT concat_ws('|', e.id, to_char(e.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
                   e.actor, e.action, e.entity, e.entity_id,
                   coalesce(e.before_state::text, 'null'), coalesce(e.after_state::text, 'null'))
$$;

-- The only write path. SECURITY DEFINER so the application role never needs INSERT on the table.
CREATE FUNCTION audit.append(p_actor text, p_action text, p_entity text, p_entity_id text,
                             p_before jsonb, p_after jsonb)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = audit, public AS $$
DECLARE
  e audit.event;
  genesis constant bytea := decode(repeat('00', 32), 'hex');
BEGIN
  -- Serialize appends: the chain needs a single, gap-free order even under concurrent writers.
  PERFORM pg_advisory_xact_lock(hashtext('audit.event.chain'));

  e.id := nextval('audit.event_id_seq');
  e.occurred_at := clock_timestamp();
  e.actor := p_actor; e.action := p_action; e.entity := p_entity; e.entity_id := p_entity_id;
  e.before_state := p_before; e.after_state := p_after;
  SELECT coalesce((SELECT hash FROM audit.event ORDER BY id DESC LIMIT 1), genesis) INTO e.prev_hash;
  e.hash := digest(e.prev_hash || convert_to(audit.canonical(e), 'UTF8'), 'sha256');

  INSERT INTO audit.event SELECT e.*;
  RETURN e.id;
END $$;

-- WORM: rows can never be changed or removed through SQL, whatever table privileges the caller has.
CREATE FUNCTION audit.forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit.event is append-only (% blocked)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER event_no_update   BEFORE UPDATE OR DELETE ON audit.event
  FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation();
CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON audit.event
  FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_mutation();

-- Walk the chain; returns the first row whose link or content does not match (no rows = chain intact).
CREATE FUNCTION audit.verify() RETURNS TABLE(broken_at bigint, reason text)
LANGUAGE plpgsql STABLE AS $$
DECLARE
  r audit.event;
  expected_prev bytea := decode(repeat('00', 32), 'hex');
BEGIN
  FOR r IN SELECT * FROM audit.event ORDER BY id LOOP
    IF r.prev_hash <> expected_prev THEN
      broken_at := r.id; reason := 'prev_hash does not link to previous row (row deleted or reordered)';
      RETURN NEXT; RETURN;
    END IF;
    IF r.hash <> digest(r.prev_hash || convert_to(audit.canonical(r), 'UTF8'), 'sha256') THEN
      broken_at := r.id; reason := 'content does not match its hash (row modified)';
      RETURN NEXT; RETURN;
    END IF;
    expected_prev := r.hash;
  END LOOP;
END $$;
