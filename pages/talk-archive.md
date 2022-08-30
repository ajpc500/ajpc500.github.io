---
title: "Previous Talks"
layout: single
permalink: /talks/
author_profile: true
---

* TOC
{:toc}

## Blue Team Con 2022

> Going Atomic: The Strengths and Weaknesses of a Technique-centric Purple Teaming Approach

Atomic purple teaming, i.e. testing individual permutations of offensive techniques outside of a scenario-based exercise, offers an approach that can maximise kill chain coverage and provides a means to benchmark a SOC's detective capability.

Initially, the methodology for atomic testing will be presented, alongside example results from a typical engagement. We'll evaluate the significant data set that such testing can produce - e.g. which test cases produce telemetry, which produce alerts, which were prevented - and consider its application in informing SOC strategy, demonstrating Return on Investment, and providing insight into general security posture.

This empirical, data-driven approach is invaluable in developing a bottom-up view of our defenses, i.e. understanding how our detection stack fares when faced with the tactics, techniques and procedures of legitimate actors, but it is not a one-stop shop for adversary emulation. As such, this talk will consider the limitations of such an approach, and how other supplementary collaborative testing can offer a more complete view of detective capability.

**NOTE:** This talk was not recorded, so I've produced a write-up of the content as a reference [here]({{ site.baseurl }}/talks/Blue-Team-Con-Going-Atomic/).

[Presentation Slides]({{ site.baseurl }}/files/btc.pdf)


## BlackHat USA 2021

> Breaking Network Segregation Using Esoteric Command & Control Channels

This talk explores the weaponization of esoteric internal command and control (C2) channels and their use for lateral movement. The following esoteric channels are explored:
- C2 into VMs through vCenter and Guest Additions
- C2 using arbitrary network printers and print jobs
- C2 over Remote Desktop mapped drives and file shares 
- C2 using LDAP attributes 

[Presentation Slides](http://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Coote-Im-A-Hacker-Get-Me-Out-Of-Here-Breaking-Network-Segregation-Using-Esoteric-Command-Control-Channels.pdf)

<iframe width="560" height="315" src="https://www.youtube.com/embed/tQAZx0uXGMo" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## RSA Conference 2021

> Beyond Public Buckets: Lessons Learned on Attack Detection in the Cloud`

The cloud has changed the nature of both offensive and defensive security. Leveraging experiences with a number of large enterprises, this session highlights common pitfalls and presents an approach to building effective cloud detection in an organization. It demonstrates how to automatically verify detection, to allow security to keep pace with the changes in the environment.

[Presentation Slides](https://urldefense.com/v3/__https://static.rainfocus.com/rsac/us21/sess/1602603775380001z14i/finalwebsite/2021_USA21_AIR-T14_01_Beyond-Public-Buckets-Lessons-Learned-on-Attack-Detection-in-the-Cloud_1620762811856001MAw7.pdf__;!!LpKI!yGg880wPgxBDdybCTwqpHKycbz61K8SA3VOyIceMyO7CIDDUzqdmX94fkQdQ_574OQ$%20[static[.]rainfocus[.]com]])


<iframe width="560" height="315" src="https://www.youtube.com/embed/YvpzUpOsY7c" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## Cloud Native Security Day 2020

> Building Effective Attack Detection in the Cloud

The cloud has significantly altered the nature of attack detection, and many of the common data sources and attacker TTPs that security teams have been looking for on premise have changed or are no longer relevant. A lack of public threat intelligence has hindered development of industry knowledge bases, such as the MITRE ATT&CK framework, and the nature of many cloud-native attacker TTPs make it challenging to separate the malicious from the benign. 

Based on ﬁrst-hand experience attacking and defending large enterprises, this talk will share what Alfie and Nick have learned about detecting attacks against cloud-native environments. They will cover how the cloud has changed the detection landscape, the key data sources to leverage, and how to plan and prioritise your cloud detection use cases. They'll also discuss how to validate your detection, including a demonstration of Leonidas, an open source framework for automatically validating detection capability in the cloud.

[Presentation Slides](https://static.sched.com/hosted_files/cnsdna20/d5/CNSD-Building-Effective-Attack-Detection-In-The-Cloud.pdf)

<iframe width="560" height="315" src="https://www.youtube.com/embed/XkLXO4o2gnQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>


## F-Secure Attack Detection Fundamentals Workshops 2021

### Windows 

In the first of our 2021 Attack Detection Fundamentals workshops, Alfie and Riccardo deep-dive into advanced defense evasion and credential access techniques targeting Windows endpoints. Such tradecraft is used by sophisticated threat actors and red teams alike, and this session looks at the detection opportunities for:

- Removal of user-land API hooks
- Installation of API hooks for credential theft
- Theft of browser cookies for session hijacking

[Workshop Slides](https://www.f-secure.com/content/dam/f-secure/en/consulting/events/collaterals/digital/f-secure_attack-detection-fundamentals-workshop-1-windows_2021-04-07.pdf)

<iframe width="560" height="315" src="https://www.youtube.com/embed/h1OBjMx-R-M" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### AWS

During this workshop, Alfie and Nick demonstrate and discuss common attacker tactics, techniques, and procedures (TTPs) used in AWS environments. Starting from the perspective of compromised AWS access keys, it provides attendees with the necessary means to detect offensive tradecraft including:

- Initial enumeration and reconnaissance using stolen access keys
- Common persistence techniques, such as deploying an IAM user as a backdoor into the account
- Data exfiltration from S3 buckets

[Workshop Slides](https://www.f-secure.com/content/dam/f-secure/en/consulting/events/collaterals/digital/f-secure_attack-detection-fundamentals-workshop-3-aws_2021-04-21.pdf)

<iframe width="560" height="315" src="https://www.youtube.com/embed/JpELEMm9OsY" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## F-Secure Attack Detection Fundamentals Workshops 2020

### Initial Access

Alfie Champion and Riccardo Ancarani kicked-off the Attack Detection Fundamentals series with Initial Access. Watch to:

- Learn the techniques threat actors use to bypass mail filtering controls and obtain foothold 
- Make use of open-source tools to emulate the initial access vectors of Emotet and those used in Operation Cobalt Kitty 
- Learn how to detect these attacks using endpoint logs or memory analysis

<iframe width="560" height="315" src="https://www.youtube.com/embed/DDK_hC90kR8" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### Discovery and Lateral Movement

Alfie Champion led our third workshop of the series where he explores and demos opportunities to detect an attacker:

- Detect an attacker as they seek to discover high-value assets within your environment, including file shares and Active Directory groups.  
- Observe how attackers could pivot through open shares to hide their lateral movement, using C3 as an example.  
- Identify detection strategies for lateral movement using legitimate system administration tools.

<iframe width="560" height="315" src="https://www.youtube.com/embed/Pv8eHC1a_bc" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>