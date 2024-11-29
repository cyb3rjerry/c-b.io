---
aliases: ["posts", "articles", "blog", "showcase", "docs"]
title: "Threat hunting for shits and giggles"
author: "Cedric 'Cyb3rjerry' Brisson"
tags: ["threat hunting", "reverse engineering", "cybersecurity"]
type: "postcard"
toc: true
date: "2024-11-28"
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

1. Search By IP Address
2. Advanced Search
3. AttackCapture
4. C2 Infrastructure
5. IOC Hunter
6. Global Sensors
7. Feeds

We'll focus on the one that gives us open dirs for now :)

### AttackCapture

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


I won't enumerate all of them but hopefully you've got a good idea of what all that means by now. If not, go grab a coffee or something.

P.S.: If someone at hunt.io is reading this, please normalize the casing of your triggers. It looks weird.

### Reviewing an entry

Upon clicking one of the IPs/domains, you'll see a nice list of files which you can interact with. More so, you'll also notice a bit of context such as the origin of the IP/domain and the total size of the directory.

![Example Of A Malicious Host](/images/malicious-host.png)

More so, you'll notice you get a shit ton of tags (sometimes) that nudge you at why these files are potentially malicious. If you click on the three dots to the right, you'll also get presented a few options of things you can do with those files.

![File Detail Example](/images/details-for-file.png)

From there, we can copy the raw file URL (the one that actually points to the C2) but that's not always good. Maybe since it's been scanned, the malicious actors have taken it down. This is where the `Download File or Share` comes in pretty darn handy. TL;DR, hunt.io saves those files (and their copies if they change overtime) to an S3 bucket which allows us to get access to that file even if it "doesn't exist anymore". You can also download it as a password protected zip to make sure your AV doesn't come screaming at you for downloading malware.

Funnily enough, the Chrome.exe kinda reminded me of [an article](https://www.sonicwall.com/blog/fake-google-chrome-website-tricks-users-into-installing-malware) I saw online a little while back about threat actors (TAs) running a campaign to try and fool people into "downloading chrome" by convincing people to run an executable. In the article, the show that the malicious domain is `hxxps://google[.]tw[.]cn/` which could easily fool a ton of people.

Why not dive into it?

## Chrome.exe

Before going straight into reverse engineering, I think it's worth taking a bit of time to comprehend the context behind the binary we've collected. You obviously won't be able to understand _exactly_ what it does from the get-go but it'll most likely give us a few points such as where we should start, which tools we should use, if there's any clear signs that this is malware and stuff like that. It's not obligatory but I feel like it's good practice.

### Doing a bit of recon

To fully understand exactly what we're dealing with, let's load the binary into a solid tool that my [MRE certification](https://www.mosse-institute.com/certifications/mre-certified-reverse-engineer.html) taught me about: [PEStudio](https://www.winitor.com/download2). Simply put, PEStudio parses [PE files](https://en.wikipedia.org/wiki/Portable_Executable#:~:text=The%20Portable%20Executable%20(PE)%20format,systems%2C%20and%20in%20UEFI%20environments.) and it's header to establish what the file does (from a static perspective). This gives us insight into if the file imports or exports function, the binary type, plaintext strings, which sections are present and a ton more info. Very useful too, highly recommend it. Now lets load Chrome.exe into it.

![Chrome.exe Loaded Into PEStudio](/images/pe-studio-chromeexe.png)