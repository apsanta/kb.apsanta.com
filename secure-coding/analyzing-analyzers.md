---
description: >-
  What modern static application security testing (SAST) tools can find and what
  cannot (C# Edition)
---

# Analyzing analyzers

## SAST, DAST, IAST

So you heard about SAST, DAST, probably IAST and RASP.

Simply integrate these tools into your pipeline and start to use them daily! But how can we choose them? Do I need all of them?

First of all, all tools have pros and cons.

SAST works with the source code. It has better coverage, potentially instant feedback to a developer, and tonnes of rules. A rule is also known as an analyzer. Some analyzers are better than others, and some are very noisy. As a result, it is recommended to manually adjust rules or even create your own rules. In reality, it leads to using default settings which bring a lot of false positives.

DAST works with a dynamic instance, so it is called dynamic application security testing. Obviously, you need a working instance and some time to perform a scan. The DAST tool will try to enumerate (crawl) all available endpoints and create "a map" of the application, or you can provide the map manually. After that, it acts like a fuzzer sending various parameters (also known as attack vectors) to the application. It knows what to expect as a response and can identify potential vulnerabilities this way. But you still need to "triage" finding and find a corresponding code snippet in the source code.&#x20;

It is hard to shift DAST tool "too left". So it will sit in the Testing phase or just between the  Development and the Testing, and it is okay. Scans take time, but devs want results immediately.

IAST (Interactive application security testing) is more close to DAST but has benefits of SAST. It requires an agent installed on the test machine. It is aware of the source code and can point to the vulnerable lines of code.  &#x20;

Historically, DAST tools work better with Security Misconfiguration and Access Controls. SAST for Injections and Cryptography. More or less... It is a big and exciting topic for another article.

## SAST Editions

Let's talk about SAST.

There are many players in the field, and we can try to group them into 3 categories:

* Free
  * Single language coverage
  * CLI / IDE integration
  * No central policy or security gates
  * Good for personal use
* Commercial
  * More languages
  * Some integrations (build server, CI/CD, etc.)
  * Policy / gates
* Enterprise commercial
  * Even more supported languages
  * Any integration
  * Policy / gates
  * "Deep analysis"
  * Custom "something"

Some tools can have various editions, e.g. providing some basic functionality for free and another edition with extra features that need to be paid.

Free tools can provide really nice results and be quick and efficient. However, it is harder to integrate into your CI/CD pipeline. No policy/gates mean you have to do it yourself.

{% hint style="info" %}
Free SAST doesn't mean bad. It usually means fewer features.&#x20;
{% endhint %}

Commercial tools can provide great value for the price. You don't need to implement anything extra, simply pay and use it.

Enterprise tools are more versatile. Most probably, they have been in the market for a long time. So anything that you might need, they will have it! These products cost a fortune, and to justify their price they have to be good, right? Absolutely! So they need a "deep" taint analysis to cover sources and sinks with a good level of depths. Well, it costs us time. And, I guess their engines and rules are not very optimized for the modern frameworks. Remember, they need to support almost everything we can imagine, which means less time for improvements and innovations!

## SAST at work

Some methods can be used in a "hacker" way. Running a SQL query is a good example. DbCommand.CommandText will act as a "**sink**".&#x20;

If user input came from a specific "**source**" (e.g. Controller), we may or may not vulnerability.

To know for sure, we need to check the flow between the Controller and SQLCommand. The existence of a known "**sanitizer**" should prevent vulnerability.

What if we are missing some source, sink, or sanitizer? Well, we will miss a vulnerability! Or will have a false positive if a sanitizer is unknown to the scanner.

But how can we add a custom source, sink, or sanitizer to improve the scanning quality? It depends on whether a product supports this feature.

It sounds complicated, and you may prefer to pay for good rules (sink, source, sanitizer) and let the vendor take care of them. But vendors will always try to convince you that some parts are too hard to manage. Let's try to figure it out.

