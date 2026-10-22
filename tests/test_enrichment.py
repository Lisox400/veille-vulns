import io
import unittest
import zipfile

from veille.enrichment.cvss import explain, parse_vector
from veille.enrichment.cwe import consequences_fr, mitigation_label, top_mitigations
from veille.sources.cwe import normalize_id, parse_archive, parse_xml

CWE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" xmlns:xhtml="http://www.w3.org/1999/xhtml"
                  Name="CWE" Version="4.20">
  <Weaknesses>
    <Weakness ID="89" Name="SQL Injection" Status="Stable">
      <Description>The product constructs   an SQL command.</Description>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Common_Consequences>
        <Consequence><Scope>Confidentiality</Scope><Scope>Integrity</Scope>
          <Impact>Execute Unauthorized Code or Commands</Impact></Consequence>
        <Consequence><Scope>Access Control</Scope><Impact>Some New Impact</Impact></Consequence>
      </Common_Consequences>
      <Potential_Mitigations>
        <Mitigation><Phase>Operation</Phase><Strategy>Firewall</Strategy>
          <Description><xhtml:p>Use a WAF [REF-1481].</xhtml:p></Description>
          <Effectiveness>Moderate</Effectiveness></Mitigation>
        <Mitigation><Phase>Architecture and Design</Phase><Strategy>Parameterization</Strategy>
          <Description><xhtml:p>Use prepared statements.</xhtml:p><xhtml:p>Second <xhtml:b>para</xhtml:b>.</xhtml:p></Description>
        </Mitigation>
        <Mitigation><Phase>Implementation</Phase>
          <Description>Escape input.</Description><Effectiveness>Limited</Effectiveness></Mitigation>
        <Mitigation><Phase>Implementation</Phase><Description><xhtml:p>Validate.</xhtml:p></Description>
          <Effectiveness>High</Effectiveness></Mitigation>
      </Potential_Mitigations>
    </Weakness>
  </Weaknesses>
  <Categories>
    <Category ID="1034" Name="OWASP A8" Status="Obsolete"><Summary>Insecure deserialization.</Summary></Category>
  </Categories>
</Weakness_Catalog>"""


class CweCatalogTest(unittest.TestCase):
    def setUp(self):
        self.catalog = parse_xml(CWE_XML)

    def test_parse(self):
        self.assertEqual(self.catalog.version, "4.20")
        info = self.catalog.get("89")
        self.assertEqual(info.name, "SQL Injection")
        self.assertEqual(info.description, "The product constructs an SQL command.")
        self.assertEqual(info.likelihood, "High")
        self.assertEqual(len(info.mitigations), 4)
        self.assertEqual(info.mitigations[0].description, "Use a WAF.")  # renvoi [REF] retiré
        self.assertEqual(info.mitigations[1].description, "Use prepared statements.\n\nSecond para.")
        self.assertEqual(self.catalog.get("CWE-1034").kind, "category")
        self.assertIsNone(self.catalog.get("CWE-1"))

    def test_archive(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("cwec_v4.20.xml", CWE_XML)
        self.assertEqual(len(parse_archive(buffer.getvalue())), 2)
        for bad in (b"not a zip", b""):
            with self.assertRaises(ValueError):
                parse_archive(bad)

    def test_normalize_id(self):
        self.assertEqual([normalize_id(x) for x in ("79", "cwe-79", "CWE-79 ")], ["CWE-79"] * 3)

    def test_french_labels(self):
        info = self.catalog.get("CWE-89")
        self.assertEqual(consequences_fr(info), [
            "Confidentialité, Intégrité → exécution de code ou de commandes",
            "Contrôle d'accès → Some New Impact",  # libellé inconnu : conservé en anglais
        ])
        ranked = top_mitigations(info, 4)
        self.assertEqual([m.effectiveness for m in ranked], ["High", "Moderate", "", "Limited"])
        self.assertEqual(mitigation_label(ranked[2]), "Conception · paramétrage (requêtes préparées)")


class CvssTest(unittest.TestCase):
    def test_parse_vector(self):
        self.assertEqual(parse_vector("CVSS:3.1/AV:N/AC:L"), ("3.1", {"AV": "N", "AC": "L"}))
        self.assertEqual(parse_vector("AV:N/Au:N"), ("2.0", {"AV": "N", "Au": "N"}))

    def test_v31_critical(self):
        e = explain("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(e.version, "3.1")
        self.assertIn("à distance par le réseau, sans authentification, sans interaction", e.summary)
        self.assertIn("confidentialité, l'intégrité et la disponibilité", e.summary)
        self.assertTrue(e.warning.startswith("Scénario critique"))
        self.assertEqual(dict(e.details)["Portée"].split(" :")[0], "Inchangée")

    def test_v31_local_user_interaction(self):
        e = explain("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N/E:P")
        self.assertIn("avec un accès local, avec un compte utilisateur standard, en piégeant un utilisateur", e.summary)
        self.assertIn("complexité élevée", e.summary)
        self.assertIn("Impact limité sur la confidentialité, au-delà du composant vulnérable", e.summary)
        self.assertEqual(e.warning, "")
        self.assertEqual(dict(e.details)["Maturité de l'exploit"], "Preuve de concept disponible")

    def test_v40(self):
        e = explain("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:A")
        self.assertEqual(e.version, "4.0")
        self.assertIn("Impact élevé sur la disponibilité", e.summary)
        self.assertTrue(dict(e.details)["Interaction"].startswith("Passive"))
        self.assertIn("Attaques constatées", dict(e.details)["Maturité de l'exploit"])
        self.assertNotIn("Systèmes tiers", dict(e.details))
        self.assertTrue(e.warning.startswith("Attaque à distance sans compte"))

    def test_v2(self):
        e = explain("AV:N/AC:M/Au:S/C:C/I:N/A:N")
        self.assertEqual(e.version, "2.0")
        self.assertIn("avec un compte utilisateur standard, complexité moyenne", e.summary)
        self.assertEqual(dict(e.details)["Confidentialité"], "Complet")
        self.assertEqual(e.warning, "")

    def test_invalid(self):
        for vector in ("", "n'importe quoi", "CVSS:3.1/"):
            self.assertIsNone(explain(vector))


if __name__ == "__main__":
    unittest.main()
