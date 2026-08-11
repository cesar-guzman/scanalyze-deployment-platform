import { test, expect } from '@playwright/test';

test.describe('Document Journey (GUG-103)', () => {
  test('should allow a user to upload a document and track its progress', async ({ page }) => {
    // 0. Intercept and mock config.json
    await page.route('**/config.json', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          schema_version: "3",
          config_version: "3.0.0",
          customer_id: "cust_00000000000000000000000000",
          deployment_id: "dep_00000000000000000000000000",
          account_id: "123456789012",
          region: "us-east-1",
          environment: "sandbox",
          api_endpoint: "http://localhost:5173/api",
          cognito: {
            user_pool_id: "us-east-1_000000000",
            spa_client_id: "abcdef1234567890",
            issuer_url: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_000000000",
            region: "us-east-1",
            hosted_ui_domain: "https://dep-00000000000000000000000000-identity.auth.us-east-1.amazoncognito.com",
            redirect_uri: "http://localhost:5173/callback",
            post_logout_redirect_uri: "http://localhost:5173/",
            allowed_oauth_flows: ["code"],
            pkce_required: true,
            client_secret_embedded: false
          },
          authorization: {
            allowed_token_uses: ["access"],
            action_scopes: {
              read: "scanalyze.api.v1/read",
              write: "scanalyze.api.v1/write",
              admin: "scanalyze.api.v1/admin"
            },
            policy_version: "1.0.0",
            policy_digest: "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8",
            policy_canonicalization: "rfc8785_json_canonicalization",
            customer_claim_name: "custom:customerId",
            deployment_claim_name: "custom:deployment_id",
            id_tokens_accepted: false
          },
          identity_values_authoritative: false
        })
      });
    });

    // Mock API calls
    await page.route('**/api/v2/documents', async route => {
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          schemaVersion: 'scanalyze.operation-response.v1',
          contractVersion: 'scanalyze.document-journey.v1',
          replayed: false,
          durableResponse: {
            schemaVersion: 'scanalyze.document-create-result.v1',
            contractVersion: 'scanalyze.document-journey.v1',
            operation: 'documents.create',
            documentId: 'fake-doc-123',
            status: 'UPLOAD_PENDING',
            contentType: 'application/pdf',
            createdAt: new Date().toISOString()
          },
          uploadCapability: {
            url: 'https://fake-s3-url.com/upload',
            method: 'PUT',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            requiredHeaders: { 'Content-Type': 'application/pdf' }
          }
        })
      });
    });

    await page.route('**/api/v2/documents/fake-doc-123/submit', async route => {
      await route.fulfill({ status: 202, body: '{}' });
    });

    await page.route('**/api/v2/documents/fake-doc-123', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          schemaVersion: 'scanalyze.document-status.v1',
          contractVersion: 'scanalyze.document-journey.v1',
          documentId: 'fake-doc-123',
          lifecycle: 'COMPLETED',
          currentStage: 'TERMINAL',
          stageState: 'SUCCEEDED',
          processingCondition: 'NOT_APPLICABLE',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          terminalAt: new Date().toISOString()
        })
      });
    });
    
    await page.route('**/api/v2/documents/fake-doc-123/result', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          schemaVersion: 'scanalyze.document-result.v1',
          contractVersion: 'scanalyze.document-journey.v1',
          documentType: 'bank_statement',
          resultType: 'bank_statement',
          documentId: 'fake-doc-123',
          resultId: 'result_fake-doc-123_v1',
          resultVersion: '1.0',
          provenance: { processor: { engine: 'test', model: 'test' }, producerSchemaVersion: '1.0', promptVersion: '1.0', generatedAt: new Date().toISOString() },
          data: {
             bank_name: 'Test Bank',
             transactions: [{ date: '2026-08-10', description: 'Test', amount: 100, type: 'CREDIT' }]
          },
          warnings: [],
          quality: { overall_confidence: 0.99, legibility_score: 0.99 }
        })
      });
    });

    // Prevent real S3 upload
    await page.route('https://fake-s3-url.com/upload', async route => {
      await route.fulfill({ status: 200 });
    });

    await page.goto('/');

    // Set auth session
    await page.evaluate(() => {
      const issuer = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_000000000';
      const clientId = 'abcdef1234567890';
      const key = `oidc.user:${issuer}:${clientId}`;
      sessionStorage.setItem(key, JSON.stringify({
        access_token: 'fake-token',
        id_token: 'fake-id-token',
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        profile: { sub: 'test-user' }
      }));
    });

    // 1. Navigate to the upload page
    await page.goto('/upload');

    // 2. Verify the upload page is rendered correctly
    await expect(page.getByRole('heading', { name: 'Scanalyze Upload' })).toBeVisible();
    await expect(page.locator('text=Arrastra tu archivo aquí')).toBeVisible();

    // 3. Select a mock file to upload
    const fileChooserPromise = page.waitForEvent('filechooser');
    await page.locator('text=Arrastra tu archivo aquí').click();
    const fileChooser = await fileChooserPromise;
    
    // We create a dummy buffer to simulate a PDF
    await fileChooser.setFiles({
      name: 'bank_statement_mock.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('mock pdf content')
    });

    // 4. Verify file is selected
    await expect(page.locator('text=bank_statement_mock.pdf')).toBeVisible();
    await expect(page.locator('button:has-text("Subir Documento")')).toBeEnabled();

    // 5. Submit the upload
    // Set up a route mock so we don't hit the real backend during E2E if we are running locally without it.
    // Or assume there is a mock server. We'll just click and assert navigation.
    await page.locator('button:has-text("Subir Documento")').click();

    // 6. Wait for redirect to document tracking page
    await page.waitForURL(/\/document\/[a-f0-9-]+/);

    // 7. Verify tracking page is rendered
    await expect(page.getByRole('heading', { name: 'Rastreo de Documento' })).toBeVisible();
    
    // Verify stages are listed
    await expect(page.locator('text=Ingestión')).toBeVisible();
    await expect(page.locator('text=Extracción Bancaria')).toBeVisible();
  });
});
