# Direct-path publication of images and frontend (GUG-543)

This runbook publishes the release artifacts for one non-production
environment that the owner deploys directly, by reviewing `terraform plan` per
layer and applying it. It does not use the platform-authority factory.

Everything here runs from the owner's shell with the owner's credentials.
Agents only prepare and review it. Merging this document authorizes nothing;
production stays **NO-GO**.

## What it produces

| Step | Command | Output |
|---|---|---|
| Images | `scripts/deployment/publish-direct-release.sh` | The seven images in ECR under immutable tags, SSM release metadata, and `release-images.json` with every digest |
| Service inputs | `scripts/deployment/render-direct-service-definitions.py` | `services.auto.tfvars.json`: `service_definitions` (digest-pinned, plus the OCR poller) and `alb_service_routes` for `roots/services` |
| Frontend | `scripts/deployment/publish-frontend.sh` | The SPA in `s3://scanalyze-<account>-frontend/`, with an optional CloudFront invalidation |

## Prerequisites

1. **AWS session.** An SSO session for the target account (`aws sts get-caller-identity`).
2. **Tools.** Docker with `linux/amd64` builds, `python3.11` (3.11.14) for the wheelhouses, Node and npm for the frontend.
3. **A clean checkout.** `build-push.sh` refuses to publish from a dirty worktree.
4. **ECR repositories.** Create them with immutable tags, named `<dep-ulid>/scanalyze/<service>` for the seven services, where `<dep-ulid>` is the deployment ID in lowercase with `-` instead of `_`. Either apply `roots/cicd` with `enable_codecommit = false` and `enable_codepipeline = false` and set each `ecr_repo_name` to `scanalyze/<service>`, or create them by hand:

   ```bash
   aws ecr create-repository --repository-name "<dep-ulid>/scanalyze/ingest-api" \
     --image-tag-mutability IMMUTABLE --image-scanning-configuration scanOnPush=true
   ```

5. **Base image in the same account.** Mirror a Debian-based Python 3.11.14 image into ECR and pin it by digest. The OCR image requires Debian `adduser` and CA certificates. For example:

   ```bash
   docker pull --platform linux/amd64 python:3.11.14-slim-bookworm
   docker tag python:3.11.14-slim-bookworm <account>.dkr.ecr.<region>.amazonaws.com/<dep-ulid>/scanalyze/base:3.11.14-slim-bookworm
   docker push <account>.dkr.ecr.<region>.amazonaws.com/<dep-ulid>/scanalyze/base:3.11.14-slim-bookworm
   ```

   Use the pushed `@sha256:` reference as `--base-image`.

## 1. Images

Review the plan first. The dry run makes no AWS or Docker calls:

```bash
scripts/deployment/publish-direct-release.sh \
  --account-id <account> --region us-east-1 --deployment-id <dep_ULID> \
  --base-image <account>.dkr.ecr.us-east-1.amazonaws.com/<dep-ulid>/scanalyze/base@sha256:<digest> \
  --tag pilot-$(git rev-parse --short=12 HEAD) --output release-images.json --dry-run
```

Then run the same command without `--dry-run`. The script refuses to overwrite `--output`, and `build-push.sh` refuses existing tags, so every publication needs a new tag.

## 2. Service inputs

```bash
scripts/deployment/render-direct-service-definitions.py \
  --release-images release-images.json --out services.auto.tfvars.json --desired-count 1
```

- **Template.** The reviewed sizes, ports, health checks and routes come from `deployment/express-production-routing.json`. `--desired-count 1` keeps a pilot small.
- **Service names.** Services keep the `scanalyze-<service>` names. They match the `ecs_task_role_arns` keys that `roots/global` outputs, which go into the services layer's `workload_role_arns`. Set `service_names` to the same `scanalyze-<service>` names in `roots/addons`, so its alarms and published log group names match.
- **OCR poller.** The renderer adds `scanalyze-ocr-poll-worker`, which runs the OCR image in `OCR_POLL` mode. This requires the GUG-108 runtime wiring, so `roots/services` must also set `runtime_wiring` from the data-foundation outputs. Without it the poller has no `WORKER_MODE`.

## 3. Frontend

```bash
scripts/deployment/publish-frontend.sh --account-id <account> \
  --bucket scanalyze-<account>-frontend --distribution-id <cloudfront-id> --dry-run
```

Then run it without `--dry-run`.

- **No deletes.** The upload never deletes objects and skips `config.json`, because the edge layer writes the runtime configuration (`<deployment>/config.json`) into the same bucket.
- **CORS.** Set `browser_origins = ["https://<frontend-domain>"]` in `roots/data-foundation`. Browsers can then use the presigned upload and download URLs.

## Known gaps

- The CloudFront frontend origin has no `origin_path` (`modules/edge/cloudfront.tf`), so the SPA is served from the bucket root.
- The two prefix conventions disagree: `releases/<dep>/*` in `policies/iam/promotion-role.json` and `<dep>/releases/*` in `policies/s3/frontend-bucket.json`. This runbook does not use either.
- No CloudFront bucket access policy exists in this repository yet. Confirm the edge layer grants the distribution read access before relying on the frontend URL.
- `microservices-build.yml` deliberately cannot publish (`publish` is a hard `exit 1`). Re-enabling CI publication is a separate owner decision.
