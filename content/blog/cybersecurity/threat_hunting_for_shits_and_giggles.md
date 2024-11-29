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

## Some hackers are horrible at OpSec

Not all hackers are the smartest. If you've ever played with [Shodan](https://shodan.io) or [Censys](https://censys.com), you've most likely come across open directories. What's an open dir? It's essentially when you expose the entire root of your website. It'll typically look something like this:

![image of a potato](/images/homelab.webp)

## hunt.io

Here's how [hunt.io](https://hunt.io/) defines itself:

> Hunt.io is a service that provides threat intelligence data about observed network scanning and cyberattacks. This data is collected by a worldwide distributed network of sensors. All interactions with sensors are registered, analyzed, and used to create network host profiles.

One of their services, however, is specifically interesting from a "poking and proding the internet for fun" perspective. That's their [AttackCapture](https://hunt.io/features/attackcapture) service.