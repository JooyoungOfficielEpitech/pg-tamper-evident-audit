-- Least privilege: the application can read and append, nothing else.
CREATE ROLE app LOGIN PASSWORD 'app';
GRANT USAGE ON SCHEMA audit TO app;
GRANT SELECT ON audit.event TO app;
REVOKE ALL ON FUNCTION audit.append(text, text, text, text, jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.append(text, text, text, text, jsonb, jsonb) TO app;
GRANT EXECUTE ON FUNCTION audit.verify() TO app;

-- Example business table whose every change is captured automatically.
CREATE TABLE public.record (
    id    bigserial PRIMARY KEY,
    owner text  NOT NULL,
    body  jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.record TO app;
GRANT USAGE ON SEQUENCE public.record_id_seq TO app;

CREATE FUNCTION audit.capture() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = audit, public AS $$
BEGIN
  PERFORM audit.append(
    coalesce(current_setting('app.actor', true), session_user),
    TG_OP, TG_TABLE_NAME,
    CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END::text,
    CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) END,
    CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) END);
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER record_audit AFTER INSERT OR UPDATE OR DELETE ON public.record
  FOR EACH ROW EXECUTE FUNCTION audit.capture();
