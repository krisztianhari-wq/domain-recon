"""SEO-modul egységtesztjei: csak helyi fixtúrák (example.com / RFC 2606), hálózat nélkül."""
import unittest

from app import seocheck as sc

HTML = """<!doctype html><html lang="en"><head>
<title>Example Bakery – fresh bread in Exampletown</title>
<meta name="description" content="Fresh bread, pastries and coffee, baked every morning at Example Street 1 in Exampletown.">
<meta name="viewport" content="width=device-width">
<meta property="og:title" content="Example Bakery"><meta property="og:description" content="x"><meta property="og:image" content="https://example.com/a.jpg">
<link rel="canonical" href="https://example.com/">
<link rel="alternate" hreflang="en" href="https://example.com/">
<link rel="alternate" hreflang="nl" href="https://example.com/nl/">
<link rel="alternate" hreflang="en-UK" href="https://example.com/uk/">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Bakery","name":"Example Bakery",
 "address":{"@type":"PostalAddress","streetAddress":"Example Street 1"},"telephone":"+31 50 000 0000"}</script>
<script>var hidden = "not visible";</script>
</head><body><h1>Example Bakery</h1><h3>Skipped</h3><p>Rolls from € 3.50. Call +31 50 000 0000.</p>
<img src="a.jpg" alt="Roll"><img src="b.jpg"></body></html>"""


class ParseTests(unittest.TestCase):
    def test_parse_basics(self):
        p = sc.parse_html(HTML)
        self.assertEqual(p.html_lang, "en")
        self.assertTrue(p.title.startswith("Example Bakery"))
        self.assertEqual(len(p.link_rel("canonical")), 1)
        self.assertEqual(len([l for l in p.link_rel("alternate") if l.get("hreflang")]), 3)
        self.assertEqual([lv for lv, _ in p.headings], [1, 3])
        self.assertNotIn("not visible", p.visible_text())
        self.assertEqual(len(p.jsonld), 1)

    def test_jsonld_rules(self):
        p = sc.parse_html(HTML)
        fs, facts = sc.jsonld_findings(p.jsonld, p.visible_text())
        self.assertEqual(facts["jsonld_types"], ["Bakery"])
        ids = {f["id"] for f in fs}
        self.assertIn("ld_rec", ids)            # geo, nyitvatartás… hiányzik
        self.assertNotIn("ld_req", ids)         # name + address megvan
        self.assertNotIn("ld_tel_vis", ids)     # a telefonszám látszik

    def test_jsonld_invalid_and_faq(self):
        fs, _ = sc.jsonld_findings(['{"@type": "FAQPage"}', "{broken"], "")
        ids = {f["id"] for f in fs}
        self.assertIn("ld_invalid", ids)
        self.assertIn("ld_notrich", ids)

    def test_hreflang_codes(self):
        self.assertIsNone(sc.hreflang_problems("en-GB"))
        self.assertIsNone(sc.hreflang_problems("x-default"))
        self.assertIsNotNone(sc.hreflang_problems("en-UK"))
        self.assertIsNotNone(sc.hreflang_problems("english"))

    def test_robots_policy(self):
        txt = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
        pol = {b["bot"]: b["allowed"] for b in sc.robots_policy(txt, "https://example.com/")}
        self.assertFalse(pol["GPTBot"])
        self.assertTrue(pol["OAI-SearchBot"])
        self.assertTrue(pol["Googlebot"])

    def test_score(self):
        s = sc.score([{"cat": "access", "severity": "high"}, {"cat": "headers", "severity": "high"}])
        self.assertEqual(s["by_cat"]["access"], 60)
        self.assertNotIn("headers", s["by_cat"])     # a fejléc-higiénia nem számít a pontba


def H(host, alive=True, port=443, status=200, title="Example", tech=None, location=None, ctype="text/html", ports=True):
    d = {"host": host, "alive": alive}
    if ports:
        d["ports"] = [{"port": port, "http": {"scheme": "https" if port == 443 else "http", "status": status, "title": title,
                                              "tech": tech or [], "location": location, "ctype": ctype}}]
    return d


class CandidateTests(unittest.TestCase):
    def test_filtering_and_merge(self):
        hosts = [
            H("example.com", status=301, location="https://www.example.com/"),
            H("www.example.com"),
            H("mail.example.com"),
            H("vpn.example.com", status=403),
            H("shop.example.com", tech=["WordPress"]),
            H("portal.example.com", title="Sign in to your account"),
            H("old.example.com", title="Welcome to nginx!"),
            H("files.example.com", ctype="application/json"),
            H("203.0.113.5"),
            H("gone.example.com", alive=False, ports=False),
            H("dev.example.com"),
        ]
        out = sc.candidates(hosts, "example.com")
        cands = {c["host"]: c for c in out["candidates"]}
        excl = {e["host"]: e["reason"] for e in out["excluded"]}
        self.assertIn("www.example.com", cands)            # apex+www összevonva, a www képviseli
        self.assertNotIn("example.com", cands)
        self.assertIn("example.com", cands["www.example.com"]["members"])
        self.assertTrue(cands["www.example.com"]["default"])
        self.assertIn("shop.example.com", cands)
        self.assertFalse(cands["shop.example.com"]["default"])
        self.assertEqual(excl["mail.example.com"], "infra")
        self.assertEqual(excl["vpn.example.com"], "infra")
        self.assertEqual(excl["portal.example.com"], "login")
        self.assertEqual(excl["old.example.com"], "default")
        self.assertEqual(excl["files.example.com"], "nonhtml")
        self.assertEqual(excl["203.0.113.5"], "ip")
        self.assertEqual(excl["gone.example.com"], "dead")
        self.assertLess(cands["dev.example.com"]["score"], cands["shop.example.com"]["score"])

    def test_passive_only(self):
        out = sc.candidates([{"host": "example.com", "alive": True}, {"host": "api.example.com", "alive": True}], "example.com")
        self.assertEqual([c["host"] for c in out["candidates"]], ["example.com"])
        self.assertTrue(out["candidates"][0]["default"])


if __name__ == "__main__":
    unittest.main()
