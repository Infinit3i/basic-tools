import unittest
from converter import extract_ips_and_hashes, is_valid_ip, is_valid_md5, is_valid_sha256

class TestIPAndHashValidation(unittest.TestCase):
    
    # Test valid and invalid IP addresses
    def test_valid_ip(self):
        valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        for ip in valid_ips:
            self.assertTrue(is_valid_ip(ip), f"{ip} should be a valid IP")

    def test_invalid_ip(self):
        invalid_ips = ["999.999.999.999", "256.256.256.256", "192.168.1.999", "abcd.efgh.ijkl.mnop"]
        for ip in invalid_ips:
            self.assertFalse(is_valid_ip(ip), f"{ip} should be an invalid IP")

    # Test valid MD5 hashes
    def test_valid_md5(self):
        valid_md5 = ["d41d8cd98f00b204e9800998ecf8427e", "9e107d9d372bb6826bd81d3542a419d6", "e99a18c428cb38d5f260853678922e03"]
        for md5 in valid_md5:
            self.assertTrue(is_valid_md5(md5), f"{md5} should be a valid MD5 hash")

    def test_invalid_md5(self):
        invalid_md5 = ["d41d8cd98f00b204e9800998ecf8427", "g41d8cd98f00b204e9800998ecf8427e", "12345", "abcdefg123456"]
        for md5 in invalid_md5:
            self.assertFalse(is_valid_md5(md5), f"{md5} should be an invalid MD5 hash")

    # Test valid SHA256 hashes
    def test_valid_sha256(self):
        valid_sha256 = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "6dcd4ce23d88e2ee9568ba546c007c63d0f22600e4f00b1c4552f32b82fcdc6e",
            "1e8d92a6d682f9b34064c9370b24c1dfe80ca0e185e3e44045bcfb21919ff712"
        ]
        for sha256 in valid_sha256:
            self.assertTrue(is_valid_sha256(sha256), f"{sha256} should be a valid SHA256 hash")

    def test_invalid_sha256(self):
        invalid_sha256 = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",  # Invalid length
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  # Non-hex
            "12345",  # Too short
            "abcdefg123456"
        ]
        for sha256 in invalid_sha256:
            self.assertFalse(is_valid_sha256(sha256), f"{sha256} should be an invalid SHA256 hash")
    
    # Test the function to extract IPs and hashes from text
    def test_extract_ips_and_hashes(self):
        data = """
        Here is a valid IP: 192.168.1.1
        And another valid one: 10.0.0.1
        Some invalid IP: 999.999.999.999
        Valid MD5 hash: d41d8cd98f00b204e9800998ecf8427e
        Invalid MD5 hash: d41d8cd98f00b204e9800998ecf8427
        Valid SHA256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        
        ips, md5_hashes, sha256_hashes = extract_ips_and_hashes(data)
        
        # Test that valid IPs are extracted
        self.assertIn("192.168.1.1", ips)
        self.assertIn("10.0.0.1", ips)
        # Test that invalid IP is not included
        self.assertNotIn("999.999.999.999", ips)
        
        # Test that valid MD5 hash is extracted
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", md5_hashes)
        # Test that invalid MD5 hash is not included
        self.assertNotIn("d41d8cd98f00b204e9800998ecf8427", md5_hashes)
        
        # Test that valid SHA256 hash is extracted
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256_hashes)

if __name__ == '__main__':
    unittest.main()
