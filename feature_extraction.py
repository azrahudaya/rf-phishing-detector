import re
from urllib.parse import urlparse
import whois
from datetime import datetime
import time
import requests

# List of shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|zpr\.io|gns\.io|qr\.ae|adcrun\.ch|adfa\.ly|adfoc\.us|fly2url\.com|link\.tl|sh\.st|soo\.gd|short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipurl\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|u\.nu|yourls\.org|x\.ip|zz\.gd|url\.ie|adjix\.com|b2l\.ink|b6s\.org|j\.mp|qr\.net|1url\.com|tweez\.me|v\.gd"

# 1. Using the IP Address
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])/)', url)
    return 1 if match else -1

# 2. URL Length
def url_length(url):
    if len(url) < 54:
        return -1
    elif 54 <= len(url) <= 75:
        return 0
    return 1

# 3. Shortening Service
def shortening_service(url):
    match = re.search(shortening_services, url)
    return 1 if match else -1

# 4. Having @ Symbol
def having_at_symbol(url):
    return 1 if '@' in url else -1

# 5. Double Slash Redirecting
def double_slash_redirecting(url):
    # Since the first double slash is mandatory (e.g., http://), we check for the presence of a second one
    return 1 if url.count('//') > 1 else -1

# 6. Prefix Suffix
def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else -1

# 7. Having Sub Domain
def having_sub_domain(url):
    # Count the number of dots in the URL
    num_dots = url.count('.')
    if num_dots == 1:
        return -1
    elif num_dots == 2:
        return 0
    return 1
    
# 8. SSL Final State
def ssl_final_state(url):
    try:
        # Check if the domain has a valid SSL certificate
        # This is a simplified check; a real implementation might be more robust
        response = requests.get(url, verify=True, timeout=5)
        return -1 # Legitimate
    except requests.exceptions.SSLError:
        return 1 # Phishing
    except requests.exceptions.RequestException:
        return 1 # Phishing or connection error


# 9. Domain Registration Length
def domain_reg_len(domain):
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date

        if isinstance(w.expiration_date, list):
            expiration_date = w.expiration_date[0]
        else:
            expiration_date = w.expiration_date

        age = (expiration_date - creation_date).days
        return -1 if age >= 365 else 1
    except:
        return 1

# 10. Favicon
def favicon(url, soup):
    # This check is tricky without rendering the page.
    # We'll check if the favicon is loaded from a different domain.
    try:
        favicon_link = soup.find("link", rel="icon")
        if favicon_link and urlparse(favicon_link['href']).netloc != urlparse(url).netloc:
            return 1
    except:
        pass
    return -1

# 11. Port
def port(url):
    # This is a placeholder as inspecting non-standard ports is complex and often blocked.
    # Standard ports (80, 443) are usually hidden. Presence of other ports can be suspicious.
    return -1 # Assume standard port

# 12. HTTPS Token
def https_token(url):
    return 1 if 'https' in urlparse(url).netloc else -1

# 13. Request URL
def request_url(url, soup):
    try:
        images = soup.find_all('img', src=True)
        total = len(images)
        linked_to_same = 0
        for image in images:
            if urlparse(url).netloc == urlparse(image['src']).netloc:
                linked_to_same += 1
        vids = soup.find_all('video', src=True)
        total += len(vids)
        for vid in vids:
            if urlparse(url).netloc == urlparse(vid['src']).netloc:
                linked_to_same += 1
        
        if total == 0: return -1
        
        percentage = linked_to_same / total
        
        if percentage < 0.22:
            return 1
        elif 0.22 <= percentage < 0.61:
            return 0
        else:
            return -1
    except:
        return 1

# 14. URL of Anchor
def url_of_anchor(url, soup):
    try:
        anchors = soup.find_all('a', href=True)
        total = len(anchors)
        if total == 0: return -1

        unsafe_count = 0
        for anchor in anchors:
            href = anchor['href']
            if href.startswith('#') or href.startswith('javascript:void(0)') or urlparse(href).netloc != urlparse(url).netloc:
                unsafe_count += 1
        
        percentage = unsafe_count / total
        if percentage < 0.31:
            return -1
        elif 0.31 <= percentage < 0.67:
            return 0
        else:
            return 1
    except:
        return 1

# 15. Links in Tags
def links_in_tags(url, soup):
    # Similar to anchor, but checking script and link tags
    return -1 # Placeholder

# 16. SFH
def sfh(url, soup):
    # Server Form Handler (SFH)
    # Checks if form action is empty, "about:blank", or points to a different domain
    try:
        forms = soup.find_all('form', action=True)
        for form in forms:
            action = form['action']
            if not action or action.lower() == "about:blank" or urlparse(action).netloc != urlparse(url).netloc:
                return 1
    except:
        pass
    return -1

# 17. Submitting to Email
def submitting_to_email(soup):
    if re.search(r"mailto:", soup.text):
        return 1
    return -1

# 18. Abnormal URL
def abnormal_url(domain):
    try:
        # Check if the hostname is present in the WHOIS info
        w = whois.whois(domain)
        return -1 if w.domain_name else 1
    except:
        return 1

# 19. Redirect
def redirect(url):
    # This requires making a request and checking history, which can be slow.
    # Placeholder for now.
    return -1

# 20. On Mouseover
def on_mouseover(soup):
    if re.search(r"onmouseover", soup.text, re.I):
        return 1
    return -1

# 21. Right Click
def right_click(soup):
    if re.search(r"event.button==2", soup.text):
        return 1
    return -1

# 22. Popup Window
def popup_window(soup):
    if re.search(r"popup|window.open", soup.text, re.I):
        return 1
    return -1

# 23. IFrame
def iframe(soup):
    return 1 if soup.find_all('iframe') else -1

# 24. Age of Domain
def age_of_domain(domain):
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date

        age = (datetime.now() - creation_date).days
        return -1 if age >= 180 else 1
    except:
        return 1

# 25. DNS Record
def dns_record(domain):
    try:
        # If we can get a WHOIS response, a DNS record must exist.
        whois.whois(domain)
        return -1
    except:
        return 1

# 26. Web Traffic
def web_traffic(url):
    # This requires a service like Alexa, which is not freely available.
    # Placeholder
    return 0

# 27. Page Rank
def page_rank(url):
    # PageRank is deprecated. Placeholder.
    return 0

# 28. Google Index
def google_index(url):
    # This requires searching Google, which is blocked for automated queries.
    # Placeholder
    return -1

# 29. Links Pointing to Page
def links_pointing_to_page(url):
    # Requires an SEO tool. Placeholder.
    return 0

# 30. Statistical Report
def statistical_report(url):
    # This would involve checking against blacklists (e.g., PhishTank).
    # Placeholder
    return -1

def extract_features(url):
    """
    Extracts the 30 features from a given URL.
    Note: Some features requiring web requests or external services are placeholders.
    """
    features = []
    
    # Simple URL-based features
    features.append(having_ip_address(url))
    features.append(url_length(url))
    features.append(shortening_service(url))
    features.append(having_at_symbol(url))
    features.append(double_slash_redirecting(url))
    features.append(prefix_suffix(url))
    features.append(having_sub_domain(url))
    
    # For many features, we need the domain name
    try:
        domain = urlparse(url).netloc
    except:
        # If parsing fails, we can't extract many features
        return None

    # These features require the domain
    features.append(ssl_final_state(url)) # This one is tricky and may need a request
    features.append(domain_reg_len(domain))
    
    # Placeholder for features requiring page content or external services
    # In a real app, you would fetch the URL content here to pass to relevant functions
    # For now, we'll use placeholders for features 10-23
    for _ in range(14):
        features.append(-1)
        
    features.append(age_of_domain(domain))
    features.append(dns_record(domain))
    
    # More placeholders
    features.append(web_traffic(url))
    features.append(page_rank(url))
    features.append(google_index(url))
    features.append(links_pointing_to_page(url))
    features.append(statistical_report(url))
    
    return features

def get_feature_names():
    return [
        "Using IP Address", "URL Length", "Shortening Service", "Having @ Symbol",
        "Double Slash Redirecting", "Prefix Suffix", "Having Sub Domain",
        "SSL Final State", "Domain Reg Length", "Favicon", "Port",
        "HTTPS Token in Domain", "Request URL", "URL of Anchor", "Links in Tags",
        "SFH", "Submitting to Email", "Abnormal URL", "Redirect",
        "On Mouseover", "Right Click", "Popup Window", "IFrame",
        "Age of Domain", "DNS Record", "Web Traffic", "Page Rank",
        "Google Index", "Links Pointing to Page", "Statistical Report"
    ] 