# peer-watch rules — draft persona
#
# Copy this file to ~/.stamp/peer-watch.md on a reviewer machine to enable
# the draft-by-default behavior used in the AGT-433 two/three-laptop validation.
#
# This persona writes all reviews to ~/.stamp/drafts/<patch_id>.md instead of
# posting to GitHub directly. An operator manually inspects drafts before posting.
# One exception: the validation test repo auto-posts so the test can confirm
# end-to-end delivery.

## Rules

### 1. Repo-specific auto-post exception (validation test repo)
If the repo is "anglepoint-engineering/stamp-peer-review-validation", auto-post
so the validation test (Test 1 / Test 2) can confirm a GitHub review appears.

  claim_seat: if_available
  post_mode: auto-post
  prompt: default
  cost_cap_usd: 5.00

### 2. Default: draft for everything else
For all other repos, write the review to a draft file without posting.

  claim_seat: if_available
  post_mode: draft
  prompt: default
