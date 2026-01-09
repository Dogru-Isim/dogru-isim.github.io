---
layout: post
title: "Index of Cybersecurity Writeups"
date: 2025-12-21
categories: articles
---

updated: Dec 24, 2025

{{ content | toc }}

# General

## Programming Language Specific Quirks

1. Common Go Mistakes<br>
Link: [Common Go Mistakes](https://100go.co/)
Generic Go mistakes with example code (that can cause security bugs of course)

2. Curated list of Ruby on Rails vulnerabilities by Brakeman
Link: [Brakeman Warning Types]https://brakemanscanner.org/docs/warning_types/
Great resource to learn about new vulnerability types and how they can emerge.
It's original purpose is to document the warnings that the Brakeman static analysis tool gives.

3. Rails send_file - Nginx X-Accel-Redirect Quirk
Link: https://projectdiscovery.io/blog/discourse-backup-disclosure-rails-send_file-quirk
Haven't read it fully yet, has something to do with X-Accel-Redirect from Nginx being inappropriately used with Rails' send_file. Too tired, brain worksn't

# Vulnerability Type: Path Traversal

## Learning Resources

1. Traversal-resistant File APIs in Go by Damien Neil<br>
Link: [Traversal-resistant File APIs](https://go.dev/blog/osroot)<br>
How to cause path traversal and how to defend against them<br>

# Vulnerability Type: CSRF

## Case Studies

### 1. Grafana CSRF

#### a) CSRF in Grafana
Link: [CSRF in Grafana](https://jub0bs.com/posts/2022-02-08-cve-2022-21703-writeup/)<br>

Key points:

1. Grafana doesn't support CORS

2. Grafana admins might set `cookie_samesite` to `none` because of point 1.

3. Safari doesn't set SameSite to Lax unlike other browsers

4. attacker.example.com exploit CSRF on victim.example.com even with SameSite set

5. Browsers perform `CORS preflight` to determine CORS settings for some requests

6. A request with `Content-Type: application/json` is enough to trigger point 6.
   
ROOT CAUSE: CORS is triggered if the "essence" of the MIME type is:

- `application/x-www-form-urlencoded`,
- `multipart/form-data`, or
- `text/plain`

BUT, if the server checks the MIME type poorly, it can interpret `text/plain; application/json` as a JSON MIME type.

The poor MIME type check:

```go
func bind(ctx *macaron.Context, obj interface{}, ifacePtr ...interface{}) {
  contentType := ctx.Req.Header.Get("Content-Type")
  if ctx.Req.Method == "POST" || ctx.Req.Method == "PUT" || len(contentType) > 0 {
    switch {
    case strings.Contains(contentType, "form-urlencoded"):
      ctx.Invoke(Form(obj, ifacePtr...))
    case strings.Contains(contentType, "multipart/form-data"):
      ctx.Invoke(MultipartForm(obj, ifacePtr...))
    case strings.Contains(contentType, "json"): // strings.Contains = BAD
      ctx.Invoke(Json(obj, ifacePtr...))
    default:
      var errors Errors
      if contentType == "" {
        errors.Add([]string{}, ERR_CONTENT_TYPE, "Empty Content-Type")
      } else {
        errors.Add([]string{}, ERR_CONTENT_TYPE, "Unsupported Content-Type")
      }
      ctx.Map(errors)
      ctx.Map(obj) // Map a fake struct so handler won't panic.
    }
  } else {
    ctx.Invoke(Form(obj, ifacePtr...))
  }
}
```

    This code is the main weakness because:

        1. Grafana requires `application/json`, browsers perform CORS preflight.

        2. CSRF can't be performed because Grafana doesn't respond to CORS preflight. No strict CSRF token checks.

        3. Attacker sends `plain/text; application/json` as Content-Type, browser interprets `application/json` as a parameter of the essence (application/text).

        4. When Grafana receives the Content-Type, it thinks the request is `application/json`.

        5. CORS preflight was not sent because browser sent `plain/text`, Grafana thought it received `application/json` because of the poor MIME type checker. CSRF was possible because the attacker website can be from the same origin (attacker.example.com grafana.example.com) or SameSite might have been set to none or the user might be using Safari. (and of course Grafana doesn't have an anti-CSRF token)

### 2. GitHub CSRF
Link: https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html

CSRF in GitHub's OAuth implementation. The problem is caused by the fact that Rails (and some other frameworks) treats HEAD requests as GET requests during routing. This means, that HEAD requests are passed to the same controller as GET requests would. Example:
```
# In the router

match "/login/oauth/authorize", # For every request with this path...
  :to => "[the controller]", # ...send it to the controller...
  :via => [:get, :post] # ... as long as it's a GET or a POST request. (or a HEAD request :wink:)

# In the controller

if request.get?
  # serve authorization page HTML
else
  # grant permissions to app (POST request logic)
end
```

This becomes a problem if the controller does not explicitly check if the incoming request is a POST request like above. Many routes are implement in a way that allows a single path in a URL to perform different actions based on the POST. This behavior is made possible with controller level checks like above.

GitHub requires POST requests to have a CSRF token to prevent CSRF attacks. This happens in a middleware I believe, it cannot be in the controller otherwise this vulnerability wouldn't be possible. The writer doesn't say where this check happens (edit: it's Rails' default CSRF protection), but when a HEAD request reaches the above controller, it gets treated as a POST request that checks the middleware that requires CSRF token in POST requests. It doesn't bypass the authentication middleware, I think, because the GET request also requires authentication. But there is a possibility that POST requests require authentication and GET request do not. This could make it possible to even bypass authentication. (GET and HEAD requests can have a body too, and this body would get processed in the POST request logic.)
