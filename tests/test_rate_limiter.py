import unittest
from unittest.mock import patch

import server


class RateLimiterHardeningTests(unittest.TestCase):
    def test_rejects_requests_after_limit(self):
        limiter = server.RateLimiter(count=2, window=60)
        self.assertTrue(limiter.allowed("ip-a"))
        self.assertTrue(limiter.allowed("ip-a"))
        self.assertFalse(limiter.allowed("ip-a"))

    def test_does_not_grow_past_key_capacity(self):
        limiter = server.RateLimiter(count=10, window=60, max_keys=2)
        self.assertTrue(limiter.allowed("ip-a"))
        self.assertTrue(limiter.allowed("ip-b"))
        self.assertFalse(limiter.allowed("ip-c"))
        self.assertEqual(len(limiter.accesses), 2)

    def test_expired_keys_make_room(self):
        limiter = server.RateLimiter(count=10, window=60, max_keys=1)
        with patch.object(server.time, "monotonic", return_value=100):
            self.assertTrue(limiter.allowed("ip-old"))
        with patch.object(server.time, "monotonic", return_value=161):
            self.assertTrue(limiter.allowed("ip-new"))
        self.assertEqual(list(limiter.accesses), ["ip-new"])


if __name__ == "__main__":
    unittest.main()
