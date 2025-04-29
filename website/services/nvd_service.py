import requests
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from typing import Dict, List, Optional

class NVDService:
    """Service for interacting with the NVD API"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {"apiKey": api_key} if api_key else {}
    
    def fetch_vulnerabilities(
        self,
        product: Optional[str] = None,
        vendor: Optional[str] = None,
        cve_id: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        results_per_page: int = 2000,
        start_index: int = 0
    ) -> Dict:
        """
        Fetch vulnerabilities from NVD API with various filters
        """
        params = {
            "resultsPerPage": min(results_per_page, 2000),  # API limit is 2000
            "startIndex": start_index
        }
        
        # Add optional parameters
        if product and vendor:
            params["cpeName"] = f"cpe:2.3:*:{vendor}:{product}"
        elif product:
            params["cpeName"] = f"cpe:2.3:*:*:{product}"
            
        if cve_id:
            params["cveId"] = cve_id
            
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
            
        if last_mod_start_date and last_mod_end_date:
            params["lastModStartDate"] = last_mod_start_date.isoformat()
            params["lastModEndDate"] = last_mod_end_date.isoformat()

        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            # Log the error and return empty results
            print(f"Error fetching vulnerabilities: {str(e)}")
            return {
                "resultsPerPage": 0,
                "startIndex": 0,
                "totalResults": 0,
                "vulnerabilities": []
            }

    def get_vulnerability_by_id(self, cve_id: str) -> Dict:
        """
        Fetch a specific vulnerability by CVE ID
        """
        return self.fetch_vulnerabilities(cve_id=cve_id)

    def get_recent_vulnerabilities(
        self,
        days_back: int = 7,
        min_severity: Optional[str] = None
    ) -> List[Dict]:
        """
        Fetch vulnerabilities from the last N days
        """
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days_back)
        
        results = self.fetch_vulnerabilities(
            last_mod_start_date=start_date,
            last_mod_end_date=end_date,
            cvss_v3_severity=min_severity
        )
        
        return results.get("vulnerabilities", [])

    def get_vulnerabilities_for_product(
        self,
        product: str,
        vendor: Optional[str] = None,
        min_severity: Optional[str] = None
    ) -> List[Dict]:
        """
        Fetch vulnerabilities for a specific product
        """
        results = self.fetch_vulnerabilities(
            product=product,
            vendor=vendor,
            cvss_v3_severity=min_severity
        )
        
        return results.get("vulnerabilities", [])
