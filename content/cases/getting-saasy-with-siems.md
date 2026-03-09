---
title: "Getting SaaSy with SIEMs — Introduction"
date: 2024-09-01
severity: "info"
status: "Closed"
category: "SOC Engineering / Guides"
threat_actor: ""
confidence: ""
tlp: "WHITE"
tags: ["SIEM", "SOC", "SaaS", "logs", "normalization", "detection-engineering"]
mitre: []
iocs: []
timeline:
  - { time: "Sep 1, 2024", action: "Field guide published", detail: "Introduction to SaaS audit log analysis for SOC analysts" }
related_cases: ["threat-hunting"]
cover: /images/getting-saasy-with-siems/confuse_soc_analyst.png
---

<blockquote>
<p>Welcome! It's so good to finally have a SOC analyst, we've got so much work to do! I know this will be a lot for you as a junior since it's all we could afford but I'm sure you can figure it out. Anyways, you're probably wondering where our logs are eh? Well for compliance reasons we've essentially been dumping everything into an ELK stack (whatever that is) but have never actually made sense of all those logs...</p>
<p>This used to work fine but now compliance is asking us to do more than just log retention but to also build detection based on all of those logs. We're a super cool R&D company so the vast majority of our stuff relies on SaaS apps! No on-prem servers here baby! Nothing but the latest and greatest here at ACME Corp. So uh... yeah. You gotta start building some detection rules ASAP so we can pass the security requirements of MegaCorp Inc so they can buy our product.</p>
<p>Good luck! Let me know when it's done!</p>
</blockquote>

Before running off to sob in a corner, you decide to take a look at the software catalog. You figure it'd at the very least give you an idea of what you'll have to deal with. You browse quickly and some names you recognize appear in front of you. Workday, 1Password, Github, Jira, they're all pretty big companies. Their logs _have_ to be somewhat simple to deal with right? You Google "Workday activity logs", find practically nothing other than this:
![](/images/getting-saasy-with-siems/workday-logs-initial-search.png)
"... there's gotta be something a bit more descriptive right?". N o p e. That's it! It's up to you to figure out something out of this. You pivot to Jira hoping it'll be better only to be met by this:
```json
{
  "data": [
    {
      "id": "<string>",
      "type": "events",
      "attributes": {
        "time": "2025-02-27T18:50:12.281Z",
        "processedAt": "2025-02-27T18:50:12.281Z",
        "action": "<string>",
  ...
        "container": [
          {
            "id": "<string>",
            "type": "<string>",
            "attributes": {},
            "links": {
              "self": "<string>",
              "alt": "<string>"
            }
          }
        ],
        "location": {
          "ip": "<string>",
          "geo": "<string>",
          "countryName": "<string>",
          "regionName": "<string>",
          "city": "<string>"
        }
      },
...
  "meta": {
    "next": "<string>",
    "page_size": 26
  },
  "links": {
    "self": "<string>",
    "prev": "<string>",
    "next": "<string>"
  }
}
```

Oh man, what did you get yourself into. How the _hell_ are you supposed to detect some threats based on this?...

---
# Preface

As someone who's been tasked with starting a SOC, I've found myself frustrated time and time again at the guidance you can find online. If you dig a little, you'll very quickly be faced with either very vague statements such as "_Incorporate threat-oriented defence into the routine security operations including those from threat frameworks such as MITRE ATT&CK and OWASP top ten_"[^1] or "_- Monitor cloud services, looking for data breaches and misconfigured ports or services._"[^2] which realistically, from an operational perspective, mean absolutely nothing.

On top of that, a large quantity of guides focus solely on self-hosted services or traditional systems such as hypervisors, operating systems, network logs and access management solutions like Active Directory[^3]. There _has_ been a slow shift towards helping practitioners adapt to cloud providers such as AWS, GCP, Azure and the likes but it still all leaves a **massive** gap. What about all these damn SaaS apps? [^4]

What happens when you're relying solely on the good will of developers who ask you to submit feature requests through the "ideas portal" (where we inevitably know is where all ideas go to die). You can't install an EDR on their systems, you can't increase your visibility with a good [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) config and the only way to gather more information about a given event would be to force the app to sit behind a proxy (which realistically still won't give you full visibility over what goes on in the backend) and yet, you are responsible for monitoring all of this.[^5]

This series of blogpost aims at helping small teams or newer SOCs adapt and integrate into the SaaS world we all inevitably live in today by reviewing various SaaS provider's audit logs and documenting known and newly found logging pitfalls each of them suffer from. Some guides out there are also incredibly boring to read through so I want to make something with a bit more zest if we're being completely honest.

**Author's note**: For most of this series I will be using XQL which is Palo Alto's query language used in a few systems. The reason behind this is simply that it's what I'm familiar with and I find it to be fairly expressive. It should be fairly simple to follow for most and readers who leverage [KQL](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-language) should feel right at home.

---
# Making sense of the chaos

Before delving too deep into logs I think a few key topics are worth covering to prevent pain points and "gotchas" further down the line while also not delving too deep into vague concepts.

## How do I interpret logs?

So you've got a mountain of JSON. It's ugly, it's nested six levels deep, and it's staring at you.

The natural instinct when you're fresh in a SOC is to treat logs like a book: read the line, interpret the words literally, react. If it says "Failure," it failed. If it says "Error," something is broken. If it says "Malicious," well, panic.

But here is the hard truth about SaaS logs: **They were not written for you.**

They were written by developers for developers to debug why their code isn't working. They weren't written to help you catch a Russian APT group. To actually find evil in this mess, you have to stop reading the text and start understanding the **mechanism** behind the text. You need to know how the machine works, otherwise, you're just chasing ghosts.

Let's look at a classic example that has caused many junior analysts to hyperventilate.

You're scrolling through your shiny new logs and you see this block repeating every 3 seconds for the last hour:
```json
{
  "event_id": "88219",
  "timestamp": "2025-02-27T14:22:01Z",
  "user_email": "finance_steve@acme.corp",
  "action": "login.attempt",
  "status": "FAILURE",
  "error_code": "INVALID_GRANT",
  "source_ip": "45.12.x.x"
}
```

**The "Face Value" Interpretation:**

> _Oh my god. Steve from Finance is under attack. Look at that! 1,200 failed logins in an hour? That's a brute force attack! Someone is hammering his account with a password spray! I need to block that IP and reset Steve's password immediately!_

**The "Under the Hood" Interpretation:**

> _Wait a second. No human can type that fast. And a brute force script would usually cycle passwords, generating `INVALID_CREDENTIALS` errors, not `INVALID_GRANT`._
>
> _I know that `INVALID_GRANT` is specific to OAuth. It usually means a Refresh Token, the thing that keeps you logged in without typing your password, has expired or been revoked. This isn't a hacker; this is Steve's old iPad trying to sync his email with a password he changed six months ago. The mail app is just dumb and keeps retrying endlessly._

See the difference?

One interpretation leads to you nuking Steve's access and writing a scary incident report. The other leads to you asking Steve if he has an old tablet in a drawer somewhere.
### Context is King (and Queen)

This applies to everything. If you don't understand how the underlying system handles authentication, or file shares, or API calls, you are going to drown in false positives.

- **Jira Logs:** If you see a user "Assign" a ticket 50 times in one second, are they malicious? Probably not. You need to know that Jira's bulk-edit feature generates a separate log event for _every single ticket_ touched in that batch job.

- **SSO Logs:** If you see a user logging in from Ireland, then the US, then Ireland again in 3 seconds, is it "Impossible Travel"? Or do you know that the authentication flow redirects the browser through a Microsoft datacenter (US) before handing the token back to the user (Ireland)?

Before you write a detection rule, take 10 minutes to understand the **normality** of the system. Google "How does [App Name] auth work?" Read the boring developer docs. If you treat the logs as literal truth without understanding the mechanism generating them, you're going to have a very bad time.

Look, I'm not going to lie to you. Reading through Atlassian's API documentation or Microsoft's 3,000-page novella on OIDC implementation is painful. It is dry, it is boring, and it is objectively the worst part of the job.

But here is the secret that nobody puts in the job description: **This is the single biggest differentiator between a "average" SOC analyst and an efficient one.**

The average analyst sees an error, guesses what it means, and spends 3 hours chasing a ghost. The great analyst spent 10 minutes reading the documentation three months ago, recognizes the behavior immediately, and closes the ticket in 30 seconds.

If you want to be efficient, if you want to stop staying late chasing false positives, and if you want to actually understand what you're looking at: **Embrace the suck.** Read the docs.
## Normalization: The "Universal Translator"

If you take nothing else away from this guide, take this: **Vendors hate agreeing on names.**

I don't know why, but it seems to be a physical impossibility for two software companies to call a user a "User."

- **Workday** calls them `initiator_id`.
- **Jira** calls them `actor.displayName`.
- **Okta** calls them `actor.alternateId`.
- **AWS** calls them `userIdentity.arn`.

If you ingest these logs "as is," you are creating a future nightmare for yourself. Why? Because when you inevitably want to search for everything "Bob" did across your company, you will have to write a query that looks like this:

```sql
dataset in (workday, jira, okta, aws)
| filter initiator_id = "bob" OR actor.displayName = "bob" OR actor.alternateId = "bob" OR userIdentity.arn contains "bob"
```

It's ugly. It's prone to errors. And when you add a 5th log source next week, you have to go back and update _every single saved query_ you have.

### Do it now, not when the building is on fire

Normalization is the art of mapping all those weird, vendor-specific field names to a single, standard set of names _before_ they hit your dashboard. It's your Rosetta Stone.

You might be tempted to skip this. "I just want to get the logs in!" you say. "I'll fix the field names later!"

**No, you won't.**

Once you start building dashboards, alerts, and reports on top of `actor.displayName`, you are stuck with it. Changing field names later means breaking every detection rule you've written. It is infinitely easier to wire the house while the walls are still open. Since you are just starting this SOC, you have a golden opportunity to do it right.
### The Standard (Keep it Simple)

You don't need a massive, enterprise-grade schema with 500 columns. You just need to pick a standard for the core things you care about and stick to it.

Here is a simple example of how you can map the chaos into order:

|**Concept**|**Your Standard (Normalized)**|**Jira Raw Field**|**Workday Raw Field**|**AWS Raw Field**|
|---|---|---|---|---|
|**Who did it?**|`user_name`|`actor.name`|`initiator`|`userIdentity.userName`|
|**Where from?**|`src_ip`|`location.ip`|`request_origin_ip`|`sourceIPAddress`|
|**What happened?**|`action_name`|`action`|`activity_name`|`eventName`|
|**Did it work?**|`action_result`|`status`|`transaction_status`|`errorCode` (if exists)|
### The Payoff

Once you set up these parsing rules (which takes maybe 10 minutes per log source), your life changes.

Remember that ugly query from before? Now, regardless of whether the log came from the Cloud, an HR app, or a Ticketing system, your threat hunting query looks like this:

```sql
dataset in (workday, jira, okta, aws)
| filter user_name = "bob"
```

Boom. One field to rule them all.

This also unlocks the holy grail of SOC work: **Cross-Source Correlation**. You can now easily ask questions like: _"Show me any user who logged in from a new IP (Okta) and immediately downloaded a list of employees (Workday)."_

If you don't normalize, that question is a complex math problem. If you _do_ normalize, it's a simple join.

Do yourself a favor: Spend the extra hour now. Future You, who is trying to investigate an incident at 3 AM, will want to kiss you.
### A Note on Modern SIEMs (The "Easy Button")

I should mention that many modern SIEMs are finally catching on to this pain. Platforms like **Palo Alto XSIAM**, Splunk, or Microsoft Sentinel often ship with built-in "Data Models" or "Schemas" that attempt to do this heavy lifting for you automatically.

For example, XSIAM will try to force incoming logs into its own data model so you can just query `xdm.source.user.username` without writing custom parsers.

**However**, do not trust them blindly. These frameworks are great for big, standard vendors (like Microsoft or AWS), but the second you plug in that niche SaaS app your R&D team loves, the auto-parsing often falls apart or maps things into the wrong fields. Always verify that the "automatic" normalization is actually putting the data where you think it is and, when possible, improve on those OOTB models.
## Messing around with the logs

Now that we have the logs and they are somewhat readable, we get to the fun part.

There is a scientific term for the most effective way to learn a new log source. It is a time-honored engineering tradition: **Fuck Around and Find Out.**

I am dead serious!

Reading the documentation is mandatory, it gives you the map. But as any explorer will tell you, the map is not the territory. Documentation is often outdated, vague, or simply fails to mention what happens when a system breaks in a specific way. It tells you how the system _should_ work; hands-on testing tells you how it _actually_ works.

### The "Split-Screen" Technique

If you want to understand Jira, or Workday, or AWS, stop looking at old logs. Go make new ones.

1. **Open the App** on your left monitor.
2. **Open your SIEM** (Live Tail/Real-time view) on your right monitor.
3. **Do something.**

Create a user. Delete a project. Change a permission. Upload a file. Then, watch the screen.

**Why do this?** Because software is weird and there is almost always more than one way to skin a cat.

Let's take **Okta** as an example. You want to detect when someone is made a **Super Admin**, right? That's SOC 101. You check the docs, find the event for "Administrator Role Granted," and write your rule.

But when you actually **Fuck Around** and try to bypass your own rule, you discover the truth:

1. **Method A ( The Front Door):** You go to the user's profile and click "Assign Admin Role."
    - **Log:** `user.account.privilege.grant`. (This is what you expected).
2. **Method B (The Side Door):** You add the user to a Group called "AWS_Admins" that happens to have the Admin Role attached to it.
    - **Log:** `group.user_membership.add`.
    - _Note:_ This log says **nothing** about admin privileges. It just says "Bob joined Group X."


If you only built a detection for `user.account.privilege.grant` because you trusted the manual, you are legally blind to Method B. You would miss the fact that Bob just became a Super Admin because you were watching the role, not the group.

You have to find all the doors, not just the one with the "Welcome" mat.

If you hadn't tested that yourself, you would have written a detection rule for `Admin_Added`, sat back with a smile on your face, and missed every single privilege escalation attempt for the next two years.


### Stress Testing your Assumptions

This phase is also about finding **blind spots**. Go try to do something "bad" (or at least "risky").

- What happens if you login with the wrong password 5 times? Does it log 5 failures? 1 failure? Does it log nothing until the account locks out?
- What happens if you change a sensitive setting and then immediately change it back? Does the system capture both, or does it "debounce" the event and show nothing?

I have seen security tools that claim to log "Everything," but when you actually test them, you realize they only log "Everything... that happens via the UI." If you do the same action via the API? Crickets.

**You cannot protect what you cannot see.** And the only way to know what you can see is to go in there, push buttons, pull levers, and see what breaks.

### Stacking: Finding the Needle by Burning the Hay

You've got your logs. They are normalized (hopefully). You've established that the API isn't dead. Now, how do you actually find threats?

You might be tempted to go download a list of "Top 10 SaaS Attacks" and start writing complex logic. **Don't.** You don't know your environment yet. If you try to hunt for advanced APTs on day one, you will fail.

Instead, use the oldest trick in the book: **Stacking** (also known as Aggregation or "Long Tail Analysis").

The philosophy is simple: **Evil is usually rare. Normal is usually frequent.**

If 5,000 users do something every day, it's probably a business process. If **one** user does something **once**, it's either a mistake, a weird edge case, or a breach. Stacking is how you find that "one."

### The "What is Normal?" Stack

Let's look at your Jira logs. You have 100,000 events from last week. You can't read them all. So, we group them.

In XQL (or SQL/KQL), the magic formula is: **Group By -> Count -> Sort (Ascending).**
```sql
dataset = jira_audit_logs
| comp count() as volume by action_name
| sort asc volume
```
**The Results:**

| **Action Name**             | **Volume** | **Interpretation**                              |
| --------------------------- | ---------- | ----------------------------------------------- |
| `issue_viewed`              | 85,402     | **Haystack.** This is normal work. Ignore it.   |
| `comment_added`             | 12,300     | **Haystack.** People talking. Ignore it.        |
| `status_changed`            | 5,400      | **Haystack.** Work moving forward.              |
| ...                         | ...        | ...                                             |
| `project_created`           | 12         | **Interesting.** Who can create projects?       |
| `webhook_created`           | 3          | **VERY Interesting.** Webhooks exfiltrate data. |
| `global_permission_deleted` | 1          | **PANIC.**                                      |
#### Why this works

You didn't need to know what a "webhook" was or search for a specific CVE. The math did the work for you. By sorting by the _least frequent_ events, the anomalies floated to the top (or bottom, depending on your sort).

This gives you a "Hunt List." You start at the count of `1` and ask: "Is this normal?"
- `global_permission_deleted`? You ask the user. "Did you mean to do this?"
- They say "Whoops, misclick." -> **False Positive** (but good catch).
- They say "I didn't do that." -> **Incident Response.**

### The "Pivot" Stack

Once you find something weird (like that Webhook creation), you pivot. Now you stack on the **User**.
```sql
dataset = jira_audit_logs
| filter action_name = "webhook_created"
| comp count() by user_name
```
If the user is "Service_Account_Jenkins," maybe it's fine. If the user is "Bob_from_Accounting," you have a problem. Bob shouldn't be making webhooks.

**Pro Tip:** Do this for _every_ new log source you onboard. It is the fastest way to understand what "Business as Usual" looks like vs. what "Weird Stuff" looks like.

## The "Real-Time" Myth (a.k.a. The Time Travel Trap)

There is one more massive betrayal specific to SaaS logs that we need to discuss before you start writing rules, and it involves the most precious resource a SOC analyst has: **Time.**

In the "good old days" of on-prem security, when a server crashed or a firewall blocked a packet, the log appeared in your SIEM instantly. You could practically watch the bits fly across the wire. It was beautiful.

SaaS does not work like that.

You see, most SaaS logs are not politely "pushed" to you the second they happen. Instead, your SIEM has to go ask for them. It wakes up every few minutes, trudges over to the vendor's API, knocks on the door, and asks: _"Hey, got anything new for me?"_

Sometimes the vendor answers immediately. Sometimes the vendor is out to lunch. This creates **Ingestion Lag**.

- **Okta** might be near real-time (usually seconds).
- **Office 365** management logs? They often decide to show up 15-60 minutes late to the party.
- **Some random HR apps?** I have seen them only make logs available once every 24 hours via a CSV dump. (I wish I was joking).

### Why this will ruin your day

Imagine you, the diligent analyst, write a detection rule that runs every **10 minutes** and looks for threats that happened in the **last 10 minutes**. Logic says this is sound, right?

**Wrong.**

If Office 365 takes **20 minutes** to deliver the log to you, your rule will run, see absolutely nothing (because the data literally hasn't arrived yet), and give you a green "Success" checkmark. By the time the log actually arrives 20 minutes later, your rule has already moved on. You just missed the attack completely because you assumed "Now" meant _Now_.

In the cloud, "Now" usually means _"Whenever the API feels like it."_

### The Fix: Trust Issues

You have to abandon the idea of "Real-Time" detection for certain log sources.

1. **Know your enemy:** Google "[Vendor Name] audit log latency" before you onboard it.
2. **Widen your gaze:** If the vendor lags by 20 minutes, make your rule look back **60 minutes**, just to be safe.
3. **Handle the overlap:** Since you are looking back further, you might catch the same event twice. Ensure your SIEM handles deduplication, otherwise, you're going to spam yourself into oblivion.

# Wrapping Up (Before Your Brain Melts)

Okay, take a breath. That was a lot of information.

We haven't actually caught any bad guys yet, and I know that feels weird. You probably want to rush off and write a rule that detects "APT29 using a Zero-Day in Workday."

But trust me: **Slow is smooth, and smooth is fast.**

If you skip the basics we covered today, your life will be miserable. You will drown in unnormalized data, you will chase "errors" that are actually normal behavior, and you will miss the real attacks because you assumed the logs worked the way the brochure said they did.

**To recap your homework:**
1. **Don't just read logs, understand the mechanism.** (Google "How does OAuth work" until it clicks).
2. **Normalize early.** (Friends don't let friends query `actor.displayName`).
3. **Fuck Around and Find Out.** (Be the chaos you want to see in the world... strictly in a testing capacity).
4. **Stack your data.** (Find the weird stuff by counting the normal stuff).
5. Validate your time. (Make sure the reported time of execution _is_ the real time of execution).

In the next part of this series, we are going to take the training wheels off. We will look at **specific SaaS providers**, tear apart their logs, and build actual, high-fidelity detection rules that will make you look like a wizard to your boss.

Until then, go break something in Jira. (And tell them I sent you).

[^1]: https://www.cyber.gc.ca/en/guidance/best-practices-setting-security-operations-centre-soc-itsap00500

[^2]: https://www.huntress.com/siem-guide/siem-implementation-guide

[^3]: https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/implementing-siem-soar-platforms/priority-logs-for-siem-ingestion-practitioner-guidance

[^4]: https://aws.amazon.com/blogs/business-productivity/cross-application-audit-log-analysis-with-aws-appfabric/

[^5]: https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility
