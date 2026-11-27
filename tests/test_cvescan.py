"""A cvescan.py ujjlenyomat-alapú detektorainak egységtesztjei (szintetikus bemenetek, nincs hálózat).
WordPress / SharePoint / Confluence a root HTML-ből vagy fejlécből; ownCloud / Jira álkliens ellen."""
import asyncio
import unittest

from app import cvescan as c


def _ids(out):
    return {x["id"] for x in out}


class _Resp:
    def __init__(self, code, payload):
        self.status_code = code
        self._p = payload

    def json(self):
        return self._p


class _Client:
    def __init__(self, routes):
        self.routes = routes

    async def get(self, url, timeout=8):
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return _Resp(404, {})


class WordPressTest(unittest.TestCase):
    def _wp(self, body):
        out = []
        c._wordpress(body, out)
        return out

    def test_full_chain_critical(self):
        for v in ("6.9.0", "6.9.4", "7.0.0", "7.0.1"):
            out = self._wp(f'<meta name="generator" content="WordPress {v}">')
            self.assertIn("wp2shell", _ids(out))
            self.assertEqual(out[0]["severity"], "critical")

    def test_68_branch_sqli_only(self):
        out = self._wp('<meta name="generator" content="WordPress 6.8.2">')
        self.assertIn("wp-sqli-60137", _ids(out))
        self.assertNotIn("wp2shell", _ids(out))

    def test_patched_clean(self):
        for v in ("6.9.5", "7.0.2", "6.8.6", "6.7.0", "7.1.0"):
            self.assertEqual(self._wp(f'<meta name="generator" content="WordPress {v}">'), [])

    def test_asset_ver_fallback(self):
        out = self._wp('<link href="/wp-includes/js/x.js?ver=7.0.0">')
        self.assertIn("wp2shell", _ids(out))

    def test_present_no_version_info(self):
        out = self._wp("<div>wp-content</div>")
        self.assertEqual([o["severity"] for o in out], ["info"])


class _Hdr(dict):
    def get(self, k, d=""):
        return {kk.lower(): vv for kk, vv in self.items()}.get(k.lower(), d)


class SharePointTest(unittest.TestCase):
    def _sp(self, build):
        out = []
        c._sharepoint(_Hdr({"MicrosoftSharePointTeamServices": f"16.0.0.{build}"}), out)
        return out

    def test_vulnerable_lines(self):
        for build in (5000, 10200, 18000):            # 2016 / 2019 / SE, mind a javítás alatt
            self.assertIn("sharepoint-missing-auth", _ids(self._sp(build)))

    def test_patched_lines(self):
        for build in (5561, 10417, 19725, 20000):     # a javított buildek és feljebb
            self.assertEqual(self._sp(build), [])

    def test_sp2013_info(self):
        out = []
        c._sharepoint(_Hdr({"MicrosoftSharePointTeamServices": "15.0.0.4420"}), out)
        self.assertEqual([o["severity"] for o in out], ["info"])


class ConfluenceFileReadTest(unittest.TestCase):
    def _conf(self, ver):
        out = []
        c._confluence(f'<meta name="ajs-version-number" content="{ver}">', out)
        return _ids(out)

    def test_21589_flagged(self):
        self.assertIn("confluence-file-read", self._conf("9.1.0"))
        self.assertIn("confluence-file-read", self._conf("10.2.10"))

    def test_21589_patched(self):
        self.assertNotIn("confluence-file-read", self._conf("9.2.26"))
        self.assertNotIn("confluence-file-read", self._conf("10.2.19"))


class AsyncProbeTest(unittest.TestCase):
    def test_owncloud(self):
        async def run(payload):
            out = []
            await c._owncloud(_Client({"/status.php": _Resp(200, payload)}), "https://h", out)
            return _ids(out)
        self.assertIn("owncloud-webdav-bypass", asyncio.run(run({"productname": "ownCloud", "versionstring": "10.13.0"})))
        self.assertEqual(asyncio.run(run({"productname": "ownCloud", "versionstring": "10.13.1"})), set())
        self.assertEqual(asyncio.run(run({"productname": "Nextcloud", "versionstring": "10.10.0"})), set())

    def test_jira(self):
        async def run(payload):
            out = []
            await c._jira(_Client({"/rest/api/2/serverInfo": _Resp(200, payload)}), "https://h", out)
            return _ids(out)
        self.assertIn("jira-file-read", asyncio.run(run({"version": "9.12.0", "deploymentType": "DataCenter"})))
        self.assertIn("jira-file-read", asyncio.run(run({"version": "11.3.11"})))
        self.assertEqual(asyncio.run(run({"version": "10.3.26"})), set())


if __name__ == "__main__":
    unittest.main()
