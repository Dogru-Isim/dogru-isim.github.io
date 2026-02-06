---
layout: post
title: "Purple Teaming: Implementing an Elastic SIEM Rule and Bypassing It"
date: 2026-02-05
categories: articles
---

{{ content1 | toc }}

# Prelude

## Content

In this post, I share some of my experiments with Elastic SIEM. Specifically, integrating Elastic's prebuilt detection rules, finding ways to bypass them.

## Background

Ever since the inception of my journey, I was focused on offensive security. I wanted to become a red teamer or at the very least a pentester. This started with a "Web Only" perspective which then moved to "Active Directory Only" and has been moving every since. But as time passed (as it does) and I grew as a person, I learned the importance of understanding cybersecurity as a whole and more importantly, I learned to be humble enough to say I made a mistake by not taking off the blinders but I'm willing to make it right. For any cybersecurity enthusiast out there, don't make the mistake I did. Learn cybersecurity as a whole and don't skip the fundamentals. Don't just read an article and think you understand it. Practice, experiment, and implement. In this post, I wanted to show my experiments with installing a SIEM solution and creating detection rules. This was my first ever experience with blue teaming (or purple teaming) and except installing the Elastic Stack, I really enjoyed it. But get ready to see some unhinged stuff (hopefully there aren't any though)

# Introduction

Elastic is a very common logging solution used by many organizations [1.0]. Elastic provides many use cases such as security or performance metrics logging. Modern versions of Elastic works with a server-agent model. You can learn more about how this model works in [1.1]. The bare minimum Elastic agent is pretty boring. It provides very useless data from a security point of view. This is where Integrations come into play. You can deploy integrations into Elastic agents so that they collect logs from places like Sysmon and Elastic Defend (Elastic EDR). You can see a list of all integrations in [1.2]

Elastic SIEM requires detection rules to operate reliably. Therefore, security teams are responsible for installing and engineering relevant detection rules. If they are too restrictive, the SOC would get flooded and they would miss real threats. And if they are too loose, threat actors would pass right by. Elastic SIEM provides over 1300 detection rules [1.3]. Some are built with generative AI [1.4] and some are hand-made.

In this post, I share my experience with installing one of these detection rules and my efforts to bypass it.

[1.0] https://www.elastic.co/customers
[1.1] https://www.devopsschool.com/blog/what-is-elastic-agents-its-feature-and-how-it-works/
[1.2] https://www.elastic.co/guide/en/integrations/current/index.html
[1.3] https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
[1.4] https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/dga/command_and_control_ml_dga_high_sum_probability#triage-and-analysis

# Bypassing a Detection Rule

## Some Rant

The golden age for threat actors is long gone. 5 years ago, you could send a Word document with malicious macros and trick a user into enabling the macros fairly easily to compromise their machine. I remember completing TryHackMe's red teamer training where they taught how to create Office macros just to see them go (almost) obsolute (when targeting modern systems) after Microsoft disabled execution of macros inside documents that are downloaded from the internet. This lead to things like MOTW bypass (the mechanisms that Windows uses to tell if a file was downloaded from the internet) with ISO files and other alternative archiving applications which also went (somewhat) obsolute after security patches. Then came the age of Entra ID phishing with things like device code phishing and evilginx. I was once told by a red teamer that you can still plant Office macros into documents after getting access to someone's Office 365 account. I didn't test this personally though. Nevertheless, these techniques will probably also go obsolute as passkeys become the defacto authentication method in Entra ID. At that point, threat actors and red teamers will need to find alternative initial access methods like passkey phishing [2.0] and malicious browser [2.1] and other 3rd party extensions [2.2]. And of course, we shouldn't forget ClickFix variations like ConsentFix [2.3]. There are many interesting techniques that can be used by attackers: installer phishing [2.4], ClickOnce-based phishing [2.5], AI-helped phishing, voice phishing, SMS phishing, this phishing, that phishing and so on [2.6]. Even USB based phishing can become a thing again [2.7]. Afterall, MOTW bypass is not a concern in USB contained files. I am still wondering what would happen if someone managed to enter into an office room at night and placed Rubber Ducky implanted mice [2.8] on everyone's desks. How many would like to test out the brand new mouse that is seemingly still sealed inside its box.

Anyways, my point is that threat actors and red teamers need to decide which initial access technique they will choose so I need to choose an initial access technique as well.

For this side-project of mine, I decided to look at MSI installer based initial access techniques. Mainly because they are easy to make a PoC with and are somewhat common. Elastic SIEM provides a few detection rules for identifying malicious usage of msiexec. One of them is the "Potential Remote Install via Msiexec [2.9]"

[2.0] https://www.youtube.com/watch?v=xdl08cPDgtE
[2.1] https://www.youtube.com/watch?v=GG4gAhbhPH8
[2.2] https://www.reddit.com/r/programming/comments/1dcz9uj/malicious_vscode_extensions_with_millions_of/
[2.3] https://www.youtube.com/watch?v=AAiiIY-Soak
[2.4] https://vicone.com/blog/phishing-beyond-emails-how-compromised-installers-threaten-automotive-software-supply-chains
[2.5] https://www.trellix.com/blogs/research/oneclik-a-clickonce-based-red-team-campaign-simulating-apt-tactics-in-energy-infrastructure/
[2.6] https://www.google.com/search?client=firefox-b-lm&q=hp-wolf-security-threat-insights-report
[2.7] https://www.coro.net/blog/why-usb-attacks-are-back-and-how-to-prevent-them
[2.8] https://www.youtube.com/watch?v=r9SWkGPlJWM
[2.9] https://www.elastic.co/guide/en/security/8.19/potential-remote-install-via-msiexec.html

## Detection Rule: Potential Remote Install via Msiexec

According to the source, this rule is built with generative AI and has been reviewed (we don't know who reviewed it). It's described as "Identifies attempts to install a file from a remote server using MsiExec. Adversaries may abuse Windows Installers for initial access and delivery of malware." It's severity is High and is implemented with the following EQL query.

```eql
process where host.os.type == "windows" and event.type == "start" and
  process.name : "msiexec.exe" and process.args : ("-i", "/i") and process.command_line : "*http*" and
  process.args : ("/qn", "-qn", "-q", "/q", "/quiet") and
  process.parent.name : ("sihost.exe", "explorer.exe", "cmd.exe", "wscript.exe", "mshta.exe", "powershell.exe", "wmiprvse.exe", "pcalua.exe", "forfiles.exe", "conhost.exe") and
  not process.command_line : ("*--set-server=*", "*UPGRADEADD=*" , "*--url=*",
                              "*USESERVERCONFIG=*", "*RCTENTERPRISESERVER=*", "*app.ninjarmm.com*", "*zoom.us/client*",
                              "*SUPPORTSERVERSTSURI=*", "*START_URL=*", "*AUTOCONFIG=*", "*awscli.amazonaws.com*")
```

This rule creates an alert with High severity when msiexec is executed with certain flags. But there are many exceptions to this. For example, the rule doesn't alert if "zoom.us/client" is anywhere in the executed command. This can be seen in the below pictures.

![msiexec-get-caught](/assets/images/2026-02-5-purple_teaming_1_configuring_and_elastic_rule_and_bypassing_it/15_running_different_versions_of_the_payload.png)
(running different variations of msiexec)

![msiexec-alert](/assets/images/2026-02-5-purple_teaming_1_configuring_and_elastic_rule_and_bypassing_it/25_siem_caught_msiexec.png)
(example alert)

As you can see, the ones that didn't have "zoom.us/client" in the command can be detected using this rule. However, this rule failed to generate an alert when "zoom.us/client/" was used as part of the remote url path. At this point, a security engineer either needs remove this exclusion from the rule, or fine-tune it (along with some of the other exclusions) to more precise matches like "https://zoom.us/client\*".

I should also point out that this variation of the payload was still logged but without an alert, there is no real reason for a SOC analyst to dive into random logs. You can see the generated log in the below image.

![logged-but-not-detected](/assets/images/2026-02-5-purple_teaming_1_configuring_and_elastic_rule_and_bypassing_it/27_bypass_trick_logged_but_not_detected.png)

# Conclusion

As a beginner in defensive security, this side-project helped me gain more insight into the intricate world of SOC. My only regret is how much time I spent just failing to setup Elastic. Anyways, I recommend anyone interested in blue teaming or red teaming do this project as well. Any red teamer should understand the SOC's side and any blue teamer should be familiar with detection rules, false-positives, and false-negatives.

And that's it. Hope you gained something out of this post. As always, if you have questions, criticisms, or just want to reach out, you know how to find my contact details.

EOF
