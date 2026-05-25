# peer-watch rules — auto-post persona
#
# Copy this file to ~/.stamp/peer-watch.md on a reviewer machine to enable
# the auto-post behavior used in the AGT-433 two/three-laptop validation.
#
# Rules are evaluated top-to-bottom; the first matching rule wins.
# If no rule matches, the fallback is claim_seat: if_available, post_mode: auto-post.

## Rules

### 1. Repo-specific always-review rule
If the repo is "anglepoint-engineering/stamp-peer-review-validation", always claim
a seat and post the review automatically.

  claim_seat: always
  post_mode: auto-post
  prompt: default
  cost_cap_usd: 5.00

### 2. Author-keyed draft rule
If the PR author fingerprint starts with "sha256:1111" (Alice's test key), write
the review to a draft file instead of posting directly — useful for sensitive author.

  claim_seat: if_available
  post_mode: draft
  prompt: default

### 3. Path-pattern rule — security-sensitive paths
If paths_changed includes files under auth/ or security/, always claim and post.

  claim_seat: always
  post_mode: auto-post
  prompt: default
  cost_cap_usd: 5.00

### 4. Time-of-day draft fallback
Outside of business hours (before 09:00 or after 18:00 local time), write a draft
instead of posting immediately.

  claim_seat: if_available
  post_mode: draft
  prompt: default

### 5. Daily cost cap ($5)
Apply a $5 daily spend cap across all reviews. When the daily total reaches $5,
subsequent PRs are skipped (the cost_cap_usd field is inherited by the matched rule
above; this comment documents the intent for all rules).
