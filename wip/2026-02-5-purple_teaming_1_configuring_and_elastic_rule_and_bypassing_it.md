---
layout: post
title: "Purple Teaming: Implementing an Elastic SIEM Rule and Bypassing It"
date: 2026-02-05
categories: articles
---

{{ content1 | toc }}

# Prelude

## Content

In this post, I share some of my experiments with Elastic SIEM. Specifically, integrating Elastic's default detection rules, finding ways to bypass them.

## Background

Ever since the inception of my journey, I was focused on offensive security. I wanted to become a red teamer or at the very least a pentester. This started with a "Web Only" perspective which then moved to "Active Directory Only" and has been moving every since. But as time passed (as it does) and I grew as a person, I learned the importance of understanding cybersecurity as a whole and more importantly, I learned to be humble enough to say I made a mistake by not taking off the blinders but I'm willing to make it right. For any cybersecurity enthusiast out there, don't make the mistake I did. Learn cybersecurity as a whole and don't skip the fundamentals. Don't just read an article and think you understand it. Practice, experiment, and implement. In this post, I wanted to show my experiments with installing a SIEM solution and creating detection rules. This was my first ever experience with blue teaming (or purple teaming) and except installing the Elastic Stack, I really enjoyed it. But get ready to see some unhinged stuff (hopefully there aren't any though)

# Introduction

