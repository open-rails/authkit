-- parent: 15 sha256:1874db239a46c6987804f9e2b5f46ccfbfc84b7df8476ca902a1f3a28b937903
-- Recovery grants bind to this version, never to mutable contact text alone.
ALTER TABLE profiles.users ADD COLUMN credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0);

-- Cover every contact/liveness writer, including host imports. Password changes
-- advance the same version explicitly in their password/revocation transaction.
CREATE FUNCTION profiles.invalidate_recovery_grants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.email, NEW.phone_number, NEW.email_verified, NEW.phone_verified,
         NEW.banned_at, NEW.banned_until, NEW.deleted_at)
     IS DISTINCT FROM
     ROW(OLD.email, OLD.phone_number, OLD.email_verified, OLD.phone_verified,
         OLD.banned_at, OLD.banned_until, OLD.deleted_at) THEN
    NEW.credential_version := OLD.credential_version + 1;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER invalidate_recovery_grants
BEFORE UPDATE ON profiles.users
FOR EACH ROW EXECUTE FUNCTION profiles.invalidate_recovery_grants();
