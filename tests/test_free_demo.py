import unittest

from free_demo.supervisor import BAYORA_BASE, SOC_BASE, rewrite_soc_home, route_target


class FreeDemoRoutingTests(unittest.TestCase):
    def test_bayora_is_the_root_application(self):
        self.assertEqual(route_target("/")[:2], (BAYORA_BASE, "/"))
        self.assertFalse(route_target("/api/catalog")[2])

    def test_soc_root_maps_to_dashboard_and_marks_html_for_rewrite(self):
        self.assertEqual(route_target("/soc"), (SOC_BASE, "/", True))
        self.assertEqual(route_target("/soc/")[1:], ("/", True))

    def test_soc_api_prefix_and_query_are_preserved(self):
        self.assertEqual(
            route_target("/soc/api/dashboard?limit=5"),
            (SOC_BASE, "/api/dashboard?limit=5", False),
        )

    def test_soc_page_fetches_use_prefixed_api_routes(self):
        page = b"fetch('/api/dashboard?x=1'); fetch('/api/cases/update')"
        self.assertEqual(
            rewrite_soc_home(page),
            b"fetch('/soc/api/dashboard?x=1'); fetch('/soc/api/cases/update')",
        )


if __name__ == "__main__":
    unittest.main()
