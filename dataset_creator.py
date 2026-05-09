import requests
import time
from typing import List, Tuple
import json

class PhishingDatasetCreator:
    def __init__(self):
        self.legitimate_urls = []
        self.phishing_urls = []
        
    def fetch_phishing_urls_from_phishtank(self, limit=100) -> List[str]:
        """Fetch phishing URLs from PhishTank API"""
        print("🎣 Fetching phishing URLs from PhishTank...")
        
        phishing_urls = []
        
        try:
            # PhishTank requires API key for full access, but we can get recent ones
            # Note: You may need to register at https://www.phishtank.com/api_info.php
            url = "http://data.phishtank.com/data/online-valid.json"
            
            print("   Downloading PhishTank data (this may take a moment)...")
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[:limit]:
                    phish_url = entry.get('url')
                    if phish_url:
                        phishing_urls.append(phish_url)
                
                print(f"   ✓ Retrieved {len(phishing_urls)} phishing URLs from PhishTank")
            else:
                print(f"   ⚠️ Failed to fetch from PhishTank (Status: {response.status_code})")
                
        except Exception as e:
            print(f"   ⚠️ Error fetching from PhishTank: {e}")
        
        return phishing_urls
    
    def fetch_phishing_urls_from_openphish(self, limit=100) -> List[str]:
        """Fetch phishing URLs from OpenPhish"""
        print("🎣 Fetching phishing URLs from OpenPhish...")
        
        phishing_urls = []
        
        try:
            url = "https://openphish.com/feed.txt"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                phishing_urls = [u.strip() for u in urls[:limit] if u.strip()]
                print(f"   ✓ Retrieved {len(phishing_urls)} phishing URLs from OpenPhish")
            else:
                print(f"   ⚠️ Failed to fetch from OpenPhish (Status: {response.status_code})")
                
        except Exception as e:
            print(f"   ⚠️ Error fetching from OpenPhish: {e}")
        
        return phishing_urls
    
    def get_legitimate_urls(self) -> List[str]:
        """Get a curated list of legitimate popular websites"""
        print("✅ Getting legitimate website URLs...")
        
        # Top legitimate websites across various categories
        legitimate_urls = [
            # Tech companies
            "https://google.com",
            "https://microsoft.com",
            "https://apple.com",
            "https://amazon.com",
            "https://facebook.com",
            "https://twitter.com",
            "https://instagram.com",
            "https://linkedin.com",
            "https://netflix.com",
            "https://spotify.com",
            "https://adobe.com",
            "https://salesforce.com",
            "https://oracle.com",
            "https://ibm.com",
            "https://intel.com",
            
            # E-commerce
            "https://ebay.com",
            "https://walmart.com",
            "https://target.com",
            "https://bestbuy.com",
            "https://etsy.com",
            "https://aliexpress.com",
            "https://shopify.com",
            
            # Financial
            "https://paypal.com",
            "https://chase.com",
            "https://bankofamerica.com",
            "https://wellsfargo.com",
            "https://americanexpress.com",
            "https://capitalone.com",
            "https://schwab.com",
            
            # News & Media
            "https://cnn.com",
            "https://bbc.com",
            "https://nytimes.com",
            "https://theguardian.com",
            "https://reuters.com",
            "https://bloomberg.com",
            "https://forbes.com",
            
            # Education
            "https://wikipedia.org",
            "https://mit.edu",
            "https://stanford.edu",
            "https://harvard.edu",
            "https://coursera.org",
            "https://khanacademy.org",
            "https://edx.org",
            
            # Government
            "https://gov.uk",
            "https://usa.gov",
            "https://irs.gov",
            "https://usps.com",
            
            # Developer tools
            "https://github.com",
            "https://stackoverflow.com",
            "https://gitlab.com",
            "https://docker.com",
            "https://npmjs.com",
            "https://pypi.org",
            
            # Cloud services
            "https://aws.amazon.com",
            "https://azure.microsoft.com",
            "https://cloud.google.com",
            "https://heroku.com",
            "https://digitalocean.com",
            
            # Communication
            "https://zoom.us",
            "https://slack.com",
            "https://discord.com",
            "https://telegram.org",
            "https://whatsapp.com",
            
            # Travel
            "https://booking.com",
            "https://airbnb.com",
            "https://expedia.com",
            "https://tripadvisor.com",
            
            # Entertainment
            "https://youtube.com",
            "https://twitch.tv",
            "https://reddit.com",
            "https://pinterest.com",
            "https://tumblr.com",
            
            # Health
            "https://webmd.com",
            "https://mayoclinic.org",
            "https://cdc.gov",
            "https://nih.gov",
            
            # Productivity
            "https://dropbox.com",
            "https://notion.so",
            "https://trello.com",
            "https://asana.com",
            "https://evernote.com",
        ]
        
        print(f"   ✓ Added {len(legitimate_urls)} legitimate URLs")
        return legitimate_urls
    
    def create_dataset(self, output_file='dataset.txt', 
                      phishing_sources=['openphish'],
                      max_phishing=100,
                      max_legitimate=100):
        """Create the complete dataset"""
        print("\n" + "="*60)
        print("PHISHING DATASET CREATOR")
        print("="*60 + "\n")
        
        all_phishing_urls = []
        
        # Fetch phishing URLs from selected sources
        for source in phishing_sources:
            if source == 'openphish':
                urls = self.fetch_phishing_urls_from_openphish(max_phishing)
                all_phishing_urls.extend(urls)
            elif source == 'phishtank':
                urls = self.fetch_phishing_urls_from_phishtank(max_phishing)
                all_phishing_urls.extend(urls)
        
        # Remove duplicates
        all_phishing_urls = list(set(all_phishing_urls))[:max_phishing]
        
        # Get legitimate URLs
        all_legitimate_urls = self.get_legitimate_urls()[:max_legitimate]
        
        # Create dataset file
        print(f"\n📝 Creating dataset file: {output_file}")
        
        with open(output_file, 'w') as f:
            # Write header
            f.write("# Phishing Detection Dataset\n")
            f.write("# Format: URL,LABEL\n")
            f.write("# LABEL: 0 = Legitimate, 1 = Phishing\n")
            f.write("# Generated automatically\n\n")
            
            # Write legitimate URLs
            f.write("# ===== LEGITIMATE WEBSITES =====\n")
            for url in all_legitimate_urls:
                f.write(f"{url},0\n")
            
            # Write phishing URLs
            f.write("\n# ===== PHISHING WEBSITES =====\n")
            for url in all_phishing_urls:
                f.write(f"{url},1\n")
        
        print(f"\n✅ Dataset created successfully!")
        print(f"\n📊 Dataset Statistics:")
        print(f"   Legitimate URLs: {len(all_legitimate_urls)}")
        print(f"   Phishing URLs: {len(all_phishing_urls)}")
        print(f"   Total URLs: {len(all_legitimate_urls) + len(all_phishing_urls)}")
        print(f"\n💾 Saved to: {output_file}")
        print(f"\n🚀 Next step: python phishing_detector.py --train {output_file}")
        print("="*60)
        
        return len(all_legitimate_urls), len(all_phishing_urls)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Create phishing detection dataset')
    parser.add_argument('-o', '--output', default='dataset.txt', 
                       help='Output file path (default: dataset.txt)')
    parser.add_argument('-p', '--phishing', type=int, default=100,
                       help='Maximum number of phishing URLs (default: 100)')
    parser.add_argument('-l', '--legitimate', type=int, default=100,
                       help='Maximum number of legitimate URLs (default: 100)')
    parser.add_argument('-s', '--sources', nargs='+', 
                       default=['openphish'],
                       choices=['openphish', 'phishtank'],
                       help='Phishing URL sources (default: openphish)')
    
    args = parser.parse_args()
    
    creator = PhishingDatasetCreator()
    creator.create_dataset(
        output_file=args.output,
        phishing_sources=args.sources,
        max_phishing=args.phishing,
        max_legitimate=args.legitimate
    )


if __name__ == "__main__":
    main()