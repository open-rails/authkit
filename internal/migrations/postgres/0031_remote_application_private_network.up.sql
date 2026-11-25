-- A remote application the host declares (Config.RemoteApplications,
-- DeclareRemoteApplications, the bootstrap manifest) may fetch its JWKS and
-- metadata from a private network, such as an app inside the cluster; one
-- registered at run time never does.
ALTER TABLE remote_applications ADD COLUMN private_network boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN remote_applications.private_network IS
  'Whether its JWKS and metadata may be fetched from private or loopback addresses: true only for applications the host declared (configuration, DeclareRemoteApplications, the bootstrap manifest); false for any registered at run time.';
