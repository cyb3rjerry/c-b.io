---
aliases: ["posts", "articles", "blog", "showcase", "docs"]
title: "Threat hunting for shits and giggles"
author: "Cedric 'Cyb3rjerry' Brisson"
tags: ["threat hunting", "reverse engineering"]
type: "blank"
toc: true
---

# Threat hunting for shits and giggles

I'll start by saying this post is _not_ endorsed by [hunt.io](https://hunt.io/). I just happen to be a really big fan of what they're doing.


## Some hackers suck at OpSec

Not all hackers are the smartest. If you've ever played with [Shodan](https://shodan.io) or [Censys](https://censys.com), you've most likely come across open directories. What's an open dir? It's essentially when you expose the entire root of your website. It'll typically look something like this:

![Open Dir Example](/images/open-dir-example.png)

As you'll see in this blogpost, sometimes hacker expose their entire `/home/user` directory which leads to some pretty interesting findings such as valid SSH keys, cobaltstrike configs and malware sample ripe with debug info. What a time to be alive!

## hunt.io

Here's how [hunt.io](https://hunt.io/) defines itself:

> Hunt.io is a service that provides threat intelligence data about observed network scanning and cyberattacks. This data is collected by a worldwide distributed network of sensors. All interactions with sensors are registered, analyzed, and used to create network host profiles.

One of their services, however, is specifically interesting from a "poking and proding the internet for fun" perspective. That's their [AttackCapture](https://hunt.io/features/attackcapture) service.

I've been using it for roughly 2 years and to be perfectly honest, I love it. It's simple, intuitive and it gives me just enough information for free that can I [FAFO](https://en.wiktionary.org/wiki/FAFO#English) on the internet.

When first logging in, you're greeted by a handy dandy dashboard that gives you some general information about the current landscape. This includes new C2s that have been ID'd, new open directories, new blogposts and all the stuff to keep you up to date with the "latest news" threat wise. It's obviously not exhaustive but I find it a simple and pretty useful.

![hunt.io dashboard](/images/huntio-dashboard.png)

If you take a look on the left of the image, you'll notice we have three main tabs which each contain a few goodies:

1. Search
    1. By IP Address
    2. Advanced Search
2. Adversary Hunting
    1. AttackCapture
    2. C2 Infrastructure
    3. IOC Hunter
    4. Global Sensors
    5. Feeds
3. Account

We'll focus on the one that gives us open dirs for now :)

## AttackCapture

When clicking on the AttackCapture tab, you'll land on a page that's chock-full of information. We get IP addresses/URLs, a number of file, a trigger and a first seen value. To the best of my knowledge (which ain't much), they're always ordered from newest to oldest.

![AttackCapture Portal](/images/attackcapture-portal.png)

### Triggers

Before delving too deep into the information provided to us, I think it's fair to establish what a trigger is. While I couldn't find official documentation describing how it works, I'm fairly confident it's simply, as the title suggests, what triggered that URL to be flagged as potentially malicious. We'll often notice the following categories:

- **hash_match**: When one or more of the files matches a known and catalogued hash. Although this is _usually_ reliable, [it's not perfect](https://detect-respond.blogspot.com/2022/04/stop-using-hashes-for-detection-and.html).
- Keyword found: When specific filename keywords match known offensive tools. This is probably the most unreliable off all triggers for the simple reason that filenames such as `Cover Vitamins&Nucleic Acid Colour.pdf` will match for tools like [Nuclei](https://github.com/projectdiscovery/nuclei). Just to be clear, I'm not shitting on their detection. I'm just saying this trigger is the most false positive prone one.
- Triage Community: These are simply IPs/domains that were submitted by the community as being known to be malicious. These tend to be pretty reliable (until some jackass decides to spam garbage I guess)
- urlhaus: As the name suggests, it's IPs/domains found by [urlhaus](https://urlhaus.abuse.ch/)
- IOC IPs from Abuse.ch: Same as urlhaus, it's all from [abuse.ch](https://abuse.ch/)
- tweet: You get the idea by now
- Cobalt Strike Scan Signature: Infra identified as a Cobalt Strike C2

![Detect Infrastructure](/images/general-iocs-attackcapture.png)

I won't enumerate all of them but hopefully you've got a good idea of what all that means by now. If not, go grab a coffee or something.

P.S.: If someone at hunt.io is reading this, please normalize the casing of your triggers. It looks weird.

### Reviewing an entry

Upon clicking one of the IPs/domains, you'll see a nice list of files which you can interact with. More so, you'll also notice a bit of context such as the origin of the IP/domain and the total size of the directory.

![Example Of A Malicious Host](/images/malicious-host.png)

More so, you'll notice you get a shit ton of tags (sometimes) that nudge you at why these files are potentially malicious. If you click on the three dots to the right, you'll also get presented a few options of things you can do with those files.

![File Detail Example](/images/details-for-file.png)