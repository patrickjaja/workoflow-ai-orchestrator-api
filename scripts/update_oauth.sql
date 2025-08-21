-- Update OAuth provider credentials for workoflow-demo organization
-- This script updates the existing Microsoft OAuth provider with correct credentials

UPDATE oauth_providers 
SET 
    client_id = (SELECT encode(encrypt('your-client-id-here'::bytea, 'your-32-char-encryption-key-here', 'aes'), 'base64')),
    client_secret = (SELECT encode(encrypt('your-client-secret-here'::bytea, 'your-32-char-encryption-key-here', 'aes'), 'base64')),
    updated_at = NOW()
WHERE 
    organization_id = 1 
    AND provider_type = 'microsoft';