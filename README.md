# Origin-Bound Cookies (by default)

## tl;dr

We propose to make cookies bound by port and scheme, in addition to the host that set them. As an [opt-out](#opt-out), we propose that the `domain` attribute be used as a mechanism for relaxing requirements on port matching (in addition to its existing behavior of relaxing same-host matching for subdomains).

## Author
* bingler@chromium.org

## Introduction
Today, thanks to recent initiatives such as [Let's Encrypt](https://letsencrypt.org/), most sites utilize HTTPS to [secure users’ connections and to help safeguard their data](https://web.dev/why-https-matters/). [Research by Google](https://transparencyreport.google.com/https/overview) shows that 97 of the top 100 (non-Google) sites default to HTTPS, all 100 of them are compatible with HTTPS, and in the United States 95% of all sites loaded in Chrome are over an HTTPS connection. The move to HTTPS is a positive one as an insecure connection (HTTP) can allow an attacker to easily monitor and modify a user’s traffic.

This move to HTTPS highlights some problems with cookies as they’re one of the few web platform components that do not respect the [origin](https://web.dev/same-site-same-origin/#origin) of their connection:
* [Weak confidentiality](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-07#section-8.5): Cookies set by a secure origin can (by default) be read by an insecure origin. Similarly, cookies set by an origin can be read by a potentially untrusted service using a different port on the same scheme and host pair.
* [Weak integrity](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-07#section-8.6): An insecure origin can (by default) modify the set of cookies read by a secure origin. Similarly, a potentially untrusted service on an origin can modify the set of cookies read by a different port on the same scheme and host pair.

These two situations can result in an attacker monitoring a user’s activity or modifying the user’s data.

To help address some of these weaknesses, a developer may employ the [`Secure` cookie attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Secure) or the [`__Secure-` cookie prefix](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes). `Secure` and `__Secure-` can help to mitigate weak confidentiality by ensuring the browser only sends the cookie over a secure connection. `__Secure-` can also help to mitigate weak integrity by assuring the server that the given cookie was delivered securely.

Unfortunately, due their opt-in nature, these mitigations are not widespread: `Secure` currently is only used on ~40% of cookies set and `__Secure-` is only used on ~12% of cookies set. This lack of adoption means that the majority of cookies are vulnerable to attacks (see below), and while the usages of both have been trending upward over the years, they are very unlikely to approach 100% which leaves users at risk.
More so, none of the existing mechanisms are able to protect cookies from malicious activity on another port of the same host.

### Example Attacks
#### Monitoring Attack
* [NSA Cookie Monitoring](https://www.eff.org/deeplinks/2013/12/nsa-turns-cookies-and-more-surveillance-beacons) - Real World Example
  * Summary: By watching for a well known cookie sent across insecure connections on different networks, an attacker can track a user's physical location without their consent, regardless of whether the cookie was set by a secure connection originally.
* [Firesheep](https://codebutler.com/2010/10/24/firesheep/) - Real World Example
  * Summary: Attackers on the same network can capture session ID cookies from victims and use them to log themselves in, gaining unauthorized access to potentially sensitive accounts and information, regardless of whether the cookie was set by a secure connection originally.
#### Modifying Attack
* [Session Fixation](https://en.wikipedia.org/wiki/Session_fixation)
  * A victim visits an insecure page http://bank.example
  * An attacker modifies the data sent to the victim to include a new cookie, a session ID, which websites use to identify logged in users.
    * `Set-Cookie: SID=abcd1234; Domain=bank.example`
    * This new SID has a value the attacker knows.
  * The victim then visits the secure site https://login.bank.example and logs in.
  * The site, bank.example, now equates `SID=abcd1234` with the victim’s account.
  * The attacker now visits https://bank.example using the same SID, is logged into the victim’s account (due to the website matching the SID), and can perform unauthorized actions against the victim's account.

## Proposal
We propose to modify cookie handling such that cookies are bound to the origin that set them by default. This means that the cookie can not be accessed by any other origins without an explicit attribute.

By doing so we’re able to secure cookies by default and require the developer to explicitly indicate their intention through an opt-out attribute in order to relax some of these protections (See the below section for more details on the opt-out).

Origins are well understood concepts across the web platform and basing cookies around them helps to increase web platform consistency and reduces confusion.

**Examples**:
* A cookie set by origin http://example.com will only ever be sent to http://example.com. It will never be sent to https://example.com and vice-versa.
* A cookie set by origin https://example.com will only ever be sent to https://example.com(:443). It will never be sent to a different port value such as https://example.com:8443.
* A cookie set by origin https://sub.example.com will only ever be sent to https://sub.example.com. It will never be sent to another host such as https://example.com.

Once widely adopted, this proposal makes the `Secure` attribute and `__Secure-` prefix unnecessary (the `__Host-` prefix is still useful for differentiating between cookies which have/haven’t opted-out). Looking far into the future, this means that, for browsers, deprecating the handling of `Secure` becomes an option.
Due to backwards compatibility with older browsers, however, sites should continue to set cookies with `Secure` for the foreseeable future.


(This proposal builds upon and obsoletes the scheme binding portion of the [Scheme-Bound Cookies](https://github.com/mikewest/scheming-cookies) proposals)

### Opt-out
Developers may have a need to access cookies between hosts or ports on a given registrable domain; to address these needs an opt-out attribute is available in the form of the [`Domain` attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent).

The `Domain` attribute relaxes the same-host matching requirements on cookies so it seems reasonable to also use the attribute to opt-out of the port-matching requirement as its usage already indicates that a site wishes to share cookies between origins. This allows any sites that have a reason to cross port boundaries the ability to do so by leveraging an existing, related, attribute which helps to mitigate compatibility risks. 
**Importantly**, there would be no way to opt-out of scheme binding. All cookies will be bound by at least their scheme to maintain protections between secure and insecure origins.

Under this proposal, cookies with the `Domain` attribute may:
* Continue to be accessible to all hosts that [domain-match](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-06#section-5.1.3).
* Be sent between all port values (assuming the cookie meets the other requirements to be sent).

**Example**:
* A cookie with `Domain=example.com` set by origin https://example.com may be sent to the origins https://sub.example.com, https://example.com:1234, or https://sub.example.com:4567. It would never be sent to any insecure origin such as http://example.com, http://sub.example.com, or http://example.com:1234. 

## Goals
* Prevent cookies set by an origin from being read by different origins.
  * Except for cookies which developers have explicitly opted out.
* Prevent an origin’s set of cookies from being modified by a different origin.
  * Except for cookies which developers have explicitly opted out.

## Non-Goals
* Deprecate the `Secure` attribute.
* Deprecate browser support of the `Secure` attribute.
* Deprecate cookie prefixes.

## Recommended Action
* Affected sites are encouraged to fully migrate to HTTPS.
* Any cookie that needs to be accessed between ports should use the `Domain` attribute.

## Examples of Potential Impact
### User Preferences are not Shared Between Origins
Users on sites that use preference cookies to save preferences (such as dark mode, notification dismissal, language, region, etc) will find that their preference will not be shared between origins. This could mean that as a user navigates between http://example.com, https://example.com, https://sub.example.com, and http://sub.example.com their preferences will be different each time. 

If the preference cookie includes the `Domain` attribute then the cookie will be shared between hosts and ports but not between schemes. This means that a user will see their preferences preserved as they navigate between https://example.com, https://sub.example.com, and https://othersub.example.com but not if the user navigates to http://example.com.

### Incomplete HTTPS Upgrade
Pages on a site can receive different sets of cookies if they're served from http vs https due to an incomplete https upgrade (or other reasons).

For example, a subscription art site hasn't fully upgraded to https yet and so some pages are still served from http.

When a user visits the homepage they are prompted that they must log in to view the site. The user clicks the link and is brought to the secured login page, https://veryniceart.example/login.php, where they enter their credentials and are logged in. As part of the login process https://veryniceart.example/login.php sets a session cookie which will allow the user to visit the rest of the site.

From the login page the user clicks a link to enter the gallery of images http://veryniceart.example/ArtGallery.html. Unfortunately the gallery page is loaded over an insecure connection. This means that the session cookie is not sent, the user is not authenticated, and the page displays an error to the (frustrated) user. 

## Questions
### How does this affect iframes?
Loading an iframe is treated like any other request and therefore will only be sent cookies that match the origin of the request (or the scheme and domain for any `Domain` cookies).
Any cookies set by a response from that request will also be bound to the request’s origin.

### How does this affect scripts?
#### Fetching scripts
A request to get the script via the `src` attribute is the same as any other request and therefore will only be sent cookies that match the origin of the request (or the scheme and domain for any `Domain` cookies). Any cookies set by a response from that request will also be bound to the request’s origin.

For example,
```
<html>
<body>

<h1>This page is hosted at http://website.example/insecure.html</h1>
<script src="https://website.example/someScript.js"></script>

</body>
</html>
```
The browser has the following cookies stored at the start:
http://website.example: A=1
https://website.example: B=2

The request for `someScript.js` will include only the cookie “B=2” (as it is the only cookie that matches the origin).
The corresponding response includes `Set-Cookie: C=3`

Once the script is fully retrieved the browser has the following cookies stored:
http://website.example: A=1
https://website.example: B=2, C=3

#### Executing scripts
Scripts execute as part of their parent document, therefore they are only able to access cookies bound to the same origin as their parent document (or the same scheme and domain for any `Domain` cookies). 

Continuing the example from above (in “Fetching scripts”) the `someScript.js` has the following code `console.log(document.cookie);` which will print out all cookies it is able to access.

Because `someScript.js` is executed as part of http://website.example/insecure.html, when run the script will only print “A=1”.

#### Module Scripts
Script tags with the `type=module` tag follow the CORS protocol when fetching, unlike classic scripts. Without an accompanying [`crossorigin`](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/crossorigin) attribute cross-origin module scripts are implicitly `anonymous` and therefore do not include cookies (credentials) by default.

* `crossorigin=anonymous`
  * No behavior change. Cookies aren’t included on the request.
* `crossorigin=use-credentials`
  * Behavior is changed. Only cookies which match the request origin are included.

### Does this proposal obsolete [Schemeful Same-Site](https://github.com/sbingler/schemeful-same-site)?
No. These two proposals change different aspects of how the browser handles cookies.

In short Origin-Bound Cookies dictates which origins a set of cookies are allowed to be accessed by whereas Schemeful Same-Site dictates in which contexts that set of cookies can be accessed. Both must be compatible in order for the cookie to be accessible.

For example, consider the following cookie which is being created by the origin https://example.com:
`Set-Cookie: foo=bar; SameSite=Strict`

Due to the origin binding this cookie can only ever be accessed by the origin https://example.com. Additionally, due to the SameSite attribute, the cookie may not be accessed in any cross-site contexts.

So the cookie foo=bar would be accessible if a user is on https://example.com as this is both the correct origin and same-site.
The cookie would not be accessible if https://other.com iframed https://example.com as this is considered a cross-site context (even though the iframe is on the same origin as the cookie).

For more details please see [a similar question](https://github.com/sbingler/schemeful-same-site#how-do-schemeful-same-site-and-scheme-bound-cookies-differ) in the Schemeful Same-Site explainer.
