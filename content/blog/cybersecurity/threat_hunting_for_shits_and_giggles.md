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

## TOC
- [Some hackers suck at OpSec](#some-hackers-suck-at-opsec)
- [hunt.io](#huntio)
- [AttackCapture]

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

If you take a look on the left of the image, you'll notice we have three main tabs:

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

### AttackCapture
