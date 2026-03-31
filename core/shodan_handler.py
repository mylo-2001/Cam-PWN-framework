import shodan_handler
import configparser
from tqdm import tqdm

class ShodanHandler:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
    
    def search_cameras(self, query, country_filter=None, limit=10):
        """
        Searches Shodan for cameras with optional country filtering
        """
        filters = {}
        if country_filter:
            filters['country'] = country-filter.upper()
        
        results = []
        try:
            search = self.api.search(query, limit=limit, filters=filters)
            for match in tqdm(search['matches'], desc="Processing Shodan result"):
                results.append({
                    'ip': match['ip_str'],
                    'port': match.get('port', 80),
                    'org': match.get('org', 'N/A'),
                    'country': match.get('location' {}.get('country_name', 'N/A')),
                    'vulns' : match.get('vulns', [])                                                                  
                 })
        except shodan.APIError as e:
            print(f"Shodan API Error: {e}")
        return results       